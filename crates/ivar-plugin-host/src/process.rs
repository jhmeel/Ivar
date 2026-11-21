//! Separate process plugins: sensor adapters, responders (with scoped
//! credentials), AI providers and sinks.
//!
//! The process starts with an empty environment plus only the secrets its
//! manifest declares, an address space limit from memory_mb, and talks JSON
//! lines over stdin and stdout. Each call has the manifest's timeout; a
//! timeout, crash or malformed reply is a breach.

use ivar_contracts::PluginManifest;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ProcessError {
    #[error("plugin process failed to start: {0}")]
    Spawn(String),
    #[error("plugin process exceeded its timeout")]
    Timeout,
    #[error("plugin process crashed or closed its output")]
    Crash,
    #[error("plugin process replied with malformed output: {0}")]
    Malformed(String),
}

pub struct ProcessPlugin {
    child: Child,
    stdin: ChildStdin,
    replies: mpsc::Receiver<String>,
    timeout: Duration,
}

impl ProcessPlugin {
    /// `secrets` holds values for the secret names in the manifest; any
    /// other entries are not passed on.
    pub fn spawn(m: &PluginManifest, program: &str, args: &[&str], secrets: &BTreeMap<String, String>) -> Result<Self, ProcessError> {
        let mut cmd = Command::new(program);
        cmd.args(args).env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
        cmd.env("IVAR_PLUGIN", &m.name);
        cmd.env("IVAR_PLUGIN_ACTIONS", m.permissions.actions.join(","));
        for name in &m.permissions.secrets {
            if let Some(v) = secrets.get(name) {
                cmd.env(format!("IVAR_SECRET_{}", name.to_uppercase()), v);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let bytes = (m.limits.memory_mb.max(16) as libc::rlim_t) << 20;
            unsafe {
                cmd.pre_exec(move || {
                    let lim = libc::rlimit { rlim_cur: bytes, rlim_max: bytes };
                    if libc::setrlimit(libc::RLIMIT_AS, &lim) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = cmd.spawn().map_err(|e| ProcessError::Spawn(e.to_string()))?;
        let stdin = child.stdin.take().ok_or_else(|| ProcessError::Spawn("no stdin".into()))?;
        let stdout: ChildStdout = child.stdout.take().ok_or_else(|| ProcessError::Spawn("no stdout".into()))?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(ProcessPlugin { child, stdin, replies: rx, timeout: Duration::from_millis(m.limits.timeout_ms) })
    }

    pub fn call(&mut self, request: &serde_json::Value) -> Result<serde_json::Value, ProcessError> {
        writeln!(self.stdin, "{request}").map_err(|_| ProcessError::Crash)?;
        self.stdin.flush().map_err(|_| ProcessError::Crash)?;
        match self.replies.recv_timeout(self.timeout) {
            Ok(line) => serde_json::from_str(&line).map_err(|e| ProcessError::Malformed(e.to_string())),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = self.child.kill();
                Err(ProcessError::Timeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ProcessError::Crash),
        }
    }
}

impl Drop for ProcessPlugin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(timeout: u64) -> PluginManifest {
        PluginManifest::from_yaml(&format!("name: echo\nversion: 1.0.0\ntype: responder\napi: ivar.plugin/v1\npermissions:\n  secrets: [okta_api_token]\nlimits: {{ memory_mb: 64, cpu_ms_per_call: 50, timeout_ms: {timeout} }}\nsignature: sigstore\n")).unwrap()
    }

    #[test]
    fn scoped_credentials_and_timeouts() {
        let secrets: BTreeMap<String, String> = [("okta_api_token".to_string(), "t0k".to_string()), ("db_password".to_string(), "nope".to_string())].into_iter().collect();
        let script = r#"while read l; do echo "{\"env\":\"$(env | grep -c IVAR_SECRET_)\",\"okta\":\"$IVAR_SECRET_OKTA_API_TOKEN\",\"db\":\"$IVAR_SECRET_DB_PASSWORD\"}"; done"#;
        let mut p = ProcessPlugin::spawn(&manifest(2000), "/bin/sh", &["-c", script], &secrets).unwrap();
        let r = p.call(&serde_json::json!({"op": "ping"})).unwrap();
        assert_eq!(r["okta"], "t0k");
        assert_eq!(r["db"], "", "undeclared secrets are never passed");
        assert_eq!(r["env"], "1");
        let mut slow = ProcessPlugin::spawn(&manifest(100), "/bin/sh", &["-c", "sleep 5"], &secrets).unwrap();
        assert_eq!(slow.call(&serde_json::json!({})).unwrap_err(), ProcessError::Timeout);
    }
}
