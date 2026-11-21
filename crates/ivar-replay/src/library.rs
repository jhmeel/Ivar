//! The attack replay library (sections 4.2, 13.4, 16.1).
//!
//! Each incident becomes a repeatable test. A new rule, plugin, policy bundle
//! or AI model must pass the library before activation, and the learning loop
//! retrains detectors only after the retrained detector passes it.

use ivar_contracts::{PolicyContent, SecurityEvent};
use ivar_core::engine::CoreOptions;
use ivar_core::sensor::EventBuilder;
use ivar_core::{DecisionCore, EngineOutput};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Endpoint {
    pub ip: String,
    pub port: u32,
    pub host: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UserSpec {
    pub uid: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DeviceSpec {
    pub uid: String,
    pub host: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessSpec {
    pub pid: u32,
    pub name: String,
    pub parent: String,
    pub path: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpSpec {
    pub method: String,
    pub path: String,
    pub body_keys: Vec<String>,
    pub status: u32,
}

/// A compact, readable event description. `{i}` in any string is replaced
/// with the repeat index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EventSpec {
    pub activity: String,
    pub class: u32,
    pub sensor: String,
    pub sensor_type: String,
    pub src_ip: String,
    pub dst: Option<Endpoint>,
    pub user: Option<UserSpec>,
    pub roles: String,
    pub session: String,
    pub app: String,
    pub device: Option<DeviceSpec>,
    pub process: Option<ProcessSpec>,
    pub http: Option<HttpSpec>,
    pub success: Option<bool>,
    pub target: String,
    pub request_id: String,
    pub business_action: String,
    pub attrs: BTreeMap<String, String>,
    pub alerts: Vec<String>,
    pub alert_confidence: f64,
    pub value: f64,
    pub records: u64,
    pub destructive: bool,
    pub egress: String,
    pub tenant: String,
    pub decoy: String,
    pub observation_point: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Expect {
    pub decision: Option<String>,
    pub decision_in: Vec<String>,
    pub min_risk: Option<f64>,
    pub max_risk: Option<f64>,
    pub actions_include: Vec<String>,
    pub actions_exclude: Vec<String>,
    pub incident: Option<bool>,
    /// This entity key must never be contained in this step.
    pub never_contain: Vec<String>,
    pub findings_include: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Step {
    pub name: String,
    pub repeat: u32,
    pub every_ms: i64,
    pub after_ms: i64,
    pub event: EventSpec,
    pub expect: Option<Expect>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Scenario {
    pub name: String,
    pub source: String,
    pub description: String,
    /// Settings merged into the policy for this scenario.
    pub settings: BTreeMap<String, serde_json::Value>,
    /// Declarations compiled for this scenario (section 6.3).
    pub openapi: String,
    pub npm_lockfile: String,
    pub github_workflow: String,
    pub kubernetes: String,
    /// Decoys added to the policy.
    pub decoys: Vec<ivar_contracts::DecoySpec>,
    /// Rule parameter overrides: rule id to params merged into the catalog rule.
    pub rule_params: BTreeMap<String, serde_json::Value>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StepResult {
    pub step: String,
    pub decision: String,
    pub risk: f64,
    pub passed: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub scenario: String,
    pub passed: bool,
    pub steps: Vec<StepResult>,
}

fn sub(s: &str, i: u32) -> String {
    s.replace("{i}", &i.to_string())
}

pub fn build_event(spec: &EventSpec, i: u32, time: i64, seq: u64) -> SecurityEvent {
    let mut b = EventBuilder::new(if spec.class == 0 { 0 } else { spec.class }, &spec.activity, time, &sub(&spec.sensor, i), &spec.sensor_type, seq);
    if !spec.src_ip.is_empty() {
        b = b.src_ip(&sub(&spec.src_ip, i));
    }
    if let Some(d) = &spec.dst {
        b = b.dst(&sub(&d.ip, i), d.port, &sub(&d.host, i));
    }
    if let Some(u) = &spec.user {
        b = b.user(&sub(&u.uid, i), &u.kind);
    }
    if !spec.roles.is_empty() {
        b = b.roles(&spec.roles);
    }
    if !spec.session.is_empty() {
        b = b.session(&sub(&spec.session, i));
    }
    if !spec.app.is_empty() {
        b = b.app(&spec.app);
    }
    if let Some(d) = &spec.device {
        b = b.device(&sub(&d.uid, i), &sub(&d.host, i), &d.kind);
    }
    if let Some(p) = &spec.process {
        b = b.process(if p.pid == 0 { 1000 + i } else { p.pid }, &p.name, &p.parent, &sub(&p.path, i));
    }
    if let Some(h) = &spec.http {
        let keys: Vec<&str> = h.body_keys.iter().map(String::as_str).collect();
        b = b.http(&h.method, &sub(&h.path, i), &keys, h.status);
    }
    if let Some(s) = spec.success {
        b = b.status(s);
    }
    if !spec.target.is_empty() {
        b = b.target(&sub(&spec.target, i));
    }
    if !spec.request_id.is_empty() {
        b = b.request_id(&sub(&spec.request_id, i));
    }
    if !spec.business_action.is_empty() {
        b = b.business_action(&spec.business_action);
    }
    for (k, v) in &spec.attrs {
        b = b.attr(k, &sub(v, i));
    }
    for a in &spec.alerts {
        b = b.engine_alert(a, spec.alert_confidence);
    }
    if spec.value > 0.0 {
        b = b.value(spec.value);
    }
    if spec.records > 0 {
        b = b.records(spec.records);
    }
    if spec.destructive {
        b = b.destructive();
    }
    if !spec.egress.is_empty() {
        b = b.egress(&spec.egress);
    }
    if !spec.tenant.is_empty() {
        b = b.tenant(&spec.tenant);
    }
    if !spec.decoy.is_empty() {
        b = b.decoy(&spec.decoy);
    }
    if !spec.observation_point.is_empty() {
        b = b.observation_point(&spec.observation_point);
    }
    b.build()
}

fn check(e: &Expect, outs: &[EngineOutput]) -> (String, f64, Vec<String>) {
    let last = outs.last().cloned().unwrap_or_default();
    let decision = last.decision().to_string();
    let risk = last.verdicts.iter().map(|v| v.risk).fold(0.0, f64::max);
    let mut f = Vec::new();
    if let Some(d) = &e.decision {
        if &decision != d {
            f.push(format!("decision {decision}, expected {d}"));
        }
    }
    if !e.decision_in.is_empty() && !e.decision_in.contains(&decision) {
        f.push(format!("decision {decision}, expected one of {:?}", e.decision_in));
    }
    if let Some(m) = e.min_risk {
        if risk < m {
            f.push(format!("risk {risk:.2} below {m}"));
        }
    }
    if let Some(m) = e.max_risk {
        if risk > m {
            f.push(format!("risk {risk:.2} above {m}"));
        }
    }
    let actions: Vec<String> = outs.iter().flat_map(|o| o.actions.iter().map(|a| a.planned.request.action.clone())).collect();
    for a in &e.actions_include {
        if !actions.contains(a) {
            f.push(format!("action {a} missing from {actions:?}"));
        }
    }
    for a in &e.actions_exclude {
        if actions.contains(a) {
            f.push(format!("action {a} must not run"));
        }
    }
    if let Some(i) = e.incident {
        let has = outs.iter().any(|o| !o.incidents.is_empty());
        if has != i {
            f.push(format!("incident opened {has}, expected {i}"));
        }
    }
    for key in &e.never_contain {
        for o in outs {
            for v in &o.verdicts {
                if v.entity.as_ref().map(|x| x.key()) == Some(key.clone()) && v.decision == "contain" {
                    f.push(format!("{key} was contained"));
                }
            }
            for a in &o.actions {
                if a.planned.request.target.as_ref().map(|t| t.key()) == Some(key.clone()) && a.planned.request.ladder_level >= 4 {
                    f.push(format!("{key} had a level {} action", a.planned.request.ladder_level));
                }
            }
        }
    }
    let rules: Vec<String> = outs.iter().flat_map(|o| o.findings.iter().chain(o.observe_only.iter()).map(|x| x.rule.clone())).collect();
    for r in &e.findings_include {
        if !rules.contains(r) {
            f.push(format!("finding {r} missing"));
        }
    }
    (decision, risk, f)
}

/// Run one scenario against a policy.
pub fn run_scenario(s: &Scenario, base: &PolicyContent) -> ScenarioReport {
    let mut policy = base.clone();
    for (k, v) in &s.settings {
        policy.settings.insert(k.clone(), v.clone());
    }
    let mut declared = ivar_core::declare::Declarations::default();
    use ivar_core::declare as dc;
    let compiled = [
        (!s.openapi.is_empty()).then(|| dc::compile_openapi("openapi.yaml", &s.openapi)),
        (!s.npm_lockfile.is_empty()).then(|| dc::compile_npm_lockfile("package-lock.json", &s.npm_lockfile)),
        (!s.github_workflow.is_empty()).then(|| dc::compile_github_workflow("workflow.yml", &s.github_workflow)),
        (!s.kubernetes.is_empty()).then(|| dc::compile_kubernetes("k8s.yaml", &s.kubernetes)),
    ];
    for c in compiled.into_iter().flatten() {
        match c {
            Ok(d) => declared.merge(d),
            Err(e) => return ScenarioReport { scenario: s.name.clone(), passed: false, steps: vec![StepResult { step: "declarations".into(), decision: String::new(), risk: 0.0, passed: false, failures: vec![e.to_string()] }] },
        }
    }
    policy.declared = declared.to_value();
    policy.decoys.extend(s.decoys.iter().cloned());
    for (rule_id, params) in &s.rule_params {
        if let Some(mut r) = ivar_core::detect::default_rules().into_iter().find(|r| &r.rule_id == rule_id) {
            if let (Some(base), Some(extra)) = (r.params.as_object_mut(), params.as_object()) {
                for (k, v) in extra {
                    base.insert(k.clone(), v.clone());
                }
            }
            policy.rules.retain(|x| &x.rule_id != rule_id);
            policy.rules.push(r);
        }
    }
    let mut core = match DecisionCore::new(policy, CoreOptions::default()) {
        Ok(c) => c,
        Err(e) => return ScenarioReport { scenario: s.name.clone(), passed: false, steps: vec![StepResult { step: "setup".into(), decision: String::new(), risk: 0.0, passed: false, failures: vec![e.to_string()] }] },
    };
    let mut t: i64 = 1_000_000;
    let mut seqs: BTreeMap<String, u64> = BTreeMap::new();
    let mut steps = Vec::new();
    for (n, st) in s.steps.iter().enumerate() {
        let mut outs = Vec::new();
        t += st.after_ms.max(1);
        for i in 0..st.repeat.max(1) {
            if i > 0 {
                t += st.every_ms.max(1);
            }
            let sensor = sub(&st.event.sensor, i);
            let seq = seqs.entry(sensor).or_insert(0);
            *seq += 1;
            outs.push(core.process(build_event(&st.event, i, t, *seq), t));
        }
        let name = if st.name.is_empty() { format!("step {}", n + 1) } else { st.name.clone() };
        let (decision, risk, failures) = st.expect.as_ref().map(|e| check(e, &outs)).unwrap_or_else(|| (outs.last().map(|o| o.decision().to_string()).unwrap_or_default(), 0.0, vec![]));
        steps.push(StepResult { step: name, decision, risk, passed: failures.is_empty(), failures });
    }
    ScenarioReport { scenario: s.name.clone(), passed: steps.iter().all(|x| x.passed), steps }
}

pub fn parse_scenario(text: &str) -> Result<Scenario, serde_yaml::Error> {
    serde_yaml::from_str(text)
}

/// Run every scenario; the library passes only if all of them pass.
pub fn run_library(scenarios: &[Scenario], base: &PolicyContent) -> (bool, Vec<ScenarioReport>) {
    let reports: Vec<ScenarioReport> = scenarios.iter().map(|s| run_scenario(s, base)).collect();
    (reports.iter().all(|r| r.passed), reports)
}
