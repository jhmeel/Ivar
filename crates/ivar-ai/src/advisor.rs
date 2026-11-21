//! The AI layer: routes each role to its provider and applies every guardrail.

use crate::config::{AiConfig, Autonomy};
use crate::guardrails::{apply_priority_floor, redact, untrusted, verify_citations, Budget};
use crate::provider::{AiProvider, AiRequest, ProviderError};
use crate::roles::Role;
use crate::schema::validate;
use ivar_core::policy::{AutoActionContext, CedarPolicy};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const SYSTEM: &str = "You are an analyst inside an intrusion detection and prevention system. You only recommend; a deterministic policy engine decides and acts. \
Base every statement on the evidence provided and cite the evidence IDs it rests on. If the evidence does not support a conclusion, say so instead of guessing. \
Answer with JSON matching the given schema.";

/// A proposed response action. The policy engine, or a person, decides.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ActionProposal {
    pub action: String,
    pub target: String,
    pub ladder_level: u32,
    pub reason: String,
    pub reversal: String,
    pub evidence_ids: Vec<String>,
    /// approved_by_policy (A3, level 3 or below, Cedar allowed), needs_approval or advisory.
    pub disposition: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AiResult {
    pub role: String,
    pub provider: String,
    pub output: Value,
    pub rejected_claims: Vec<String>,
    pub cost_usd: f64,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AiError {
    #[error("AI is off (autonomy A0)")]
    Off,
    #[error("no provider routed for {0}")]
    NoRoute(String),
    #[error("{0}")]
    Limit(String),
    #[error("provider: {0}")]
    Provider(#[from] ProviderError),
    #[error("model output failed schema validation: {0}")]
    Schema(String),
    #[error("model {0} has not passed the attack replay library")]
    NotActivated(String),
}

pub struct AiLayer {
    pub config: AiConfig,
    providers: BTreeMap<String, Box<dyn AiProvider>>,
    budget: Budget,
    /// Providers whose current model passed the attack replay library.
    activated: BTreeSet<String>,
}

impl AiLayer {
    pub fn new(config: AiConfig, providers: BTreeMap<String, Box<dyn AiProvider>>) -> Self {
        let budget = Budget::new(config.limits.monthly_budget_usd, config.limits.max_requests_per_minute);
        AiLayer { config, providers, budget, activated: BTreeSet::new() }
    }

    /// A new model is activated only after it passes the attack replay library.
    pub fn activate(&mut self, provider: &str, replay_library_passed: bool) -> bool {
        if replay_library_passed {
            self.activated.insert(provider.to_string());
        } else {
            self.activated.remove(provider);
        }
        replay_library_passed
    }

    fn call(&mut self, name: &str, req: &AiRequest, now_ms: i64) -> Result<(Value, f64), AiError> {
        if !self.activated.contains(name) {
            return Err(AiError::NotActivated(name.into()));
        }
        self.budget.admit(name, now_ms).map_err(AiError::Limit)?;
        let p = self.providers.get(name).ok_or_else(|| AiError::NoRoute(name.into()))?;
        let r = p.complete(req)?;
        let cost = self.budget.charge(name, r.input_tokens, r.output_tokens, p.price_per_mtok());
        Ok((r.json, cost))
    }

    /// Run one role over evidence. `known_evidence` is the set of evidence
    /// IDs the claims may cite.
    pub fn run(&mut self, role: Role, input: &Value, known_evidence: &BTreeSet<String>, now_ms: i64) -> Result<AiResult, AiError> {
        if self.config.autonomy == Autonomy::Off {
            return Err(AiError::Off);
        }
        let route = self.config.provider_for(role.routing_key()).map(|(n, _)| n.to_string()).or_else(|| self.config.vetted_local().map(|(n, _)| n.to_string())).ok_or_else(|| AiError::NoRoute(role.routing_key().into()))?;
        let schema = role.schema();
        let evidence = redact(&untrusted(input), &self.config.redact);
        let req = AiRequest { system: SYSTEM.into(), prompt: format!("{}\n\n{}", role.task(), evidence), schema: schema.clone(), max_tokens: 16_000 };
        let (mut output, cost, provider) = match self.call(&route, &req, now_ms) {
            Ok((o, c)) => (o, c, route.clone()),
            Err(AiError::Provider(ProviderError::Refused(_))) => {
                // A hosted model may refuse forensic content: the vetted local model is kept ready.
                let local = self.config.vetted_local().map(|(n, _)| n.to_string()).ok_or(AiError::NoRoute("vetted local model".into()))?;
                let (o, c) = self.call(&local, &req, now_ms)?;
                (o, c, local)
            }
            Err(e) => return Err(e),
        };
        validate(&schema, &output, "$").map_err(AiError::Schema)?;
        let rejected_claims = verify_citations(&mut output, known_evidence);
        Ok(AiResult { role: role.routing_key().into(), provider, output, rejected_claims, cost_usd: cost })
    }

    /// Triage: AI may raise priority, never lower it below the deterministic floor.
    pub fn triage(&mut self, alerts: &Value, floors: &BTreeMap<String, u32>, known: &BTreeSet<String>, now_ms: i64) -> Result<AiResult, AiError> {
        let mut r = self.run(Role::TriageAnalyst, alerts, known, now_ms)?;
        if let Some(items) = r.output.get_mut("alerts").and_then(Value::as_array_mut) {
            for a in items {
                let id = a.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                let p = a.get("priority").and_then(Value::as_u64).unwrap_or(5) as u32;
                let floor = floors.get(&id).copied().unwrap_or(5);
                a["priority"] = Value::from(apply_priority_floor(p, floor));
            }
        }
        Ok(r)
    }

    /// Response advice: proposals only. At A3 a proposal at ladder level 3 or
    /// below that Cedar allows for the AI principal is approved by policy;
    /// everything else needs a person. Levels 4 to 6 always need
    /// deterministic evidence and policy approval, whichever model is connected.
    pub fn advise(&mut self, incident: &Value, known: &BTreeSet<String>, cedar: &CedarPolicy, posture: &str, now_ms: i64) -> Result<Vec<ActionProposal>, AiError> {
        let r = self.run(Role::ResponseAdvisor, incident, known, now_ms)?;
        let autonomy = self.config.autonomy;
        let mut out = Vec::new();
        for a in r.output.get("actions").and_then(Value::as_array).cloned().unwrap_or_default() {
            let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let level = a.get("ladder_level").and_then(Value::as_u64).unwrap_or(6) as u32;
            let ctx = AutoActionContext { ladder_level: level, ai_autonomy: autonomy_name(autonomy).into(), runtime_posture: posture.into(), ..Default::default() };
            let cedar_action = match level {
                0 => "record",
                1 => "throttle",
                2 => "challenge",
                3 => "block",
                _ => "contain",
            };
            let disposition = match autonomy {
                Autonomy::Bounded if level <= 3 && cedar.allow_auto("ai", cedar_action, &s("target"), &ctx).unwrap_or(false) => "approved_by_policy",
                Autonomy::Propose | Autonomy::Bounded => "needs_approval",
                _ => "advisory",
            };
            out.push(ActionProposal {
                action: s("action"),
                target: s("target"),
                ladder_level: level,
                reason: s("reason"),
                reversal: s("reversal"),
                evidence_ids: a.get("evidence_ids").and_then(Value::as_array).map(|x| x.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
                disposition: disposition.into(),
            });
        }
        Ok(out)
    }
}

fn autonomy_name(a: Autonomy) -> &'static str {
    match a {
        Autonomy::Off => "off",
        Autonomy::Advise => "advise",
        Autonomy::Propose => "propose",
        Autonomy::Bounded => "bounded",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SPEC_YAML;
    use crate::provider::{AiResponse, AnthropicProvider, HttpTransport, SecretResolver};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct Scripted {
        replies: Arc<Mutex<Vec<Result<Value, ProviderError>>>>,
        name: String,
        local: bool,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl AiProvider for Scripted {
        fn name(&self) -> &str {
            &self.name
        }
        fn price_per_mtok(&self) -> (f64, f64) {
            (4.0, 20.0)
        }
        fn is_local(&self) -> bool {
            self.local
        }
        fn complete(&self, r: &AiRequest) -> Result<AiResponse, ProviderError> {
            self.seen.lock().unwrap().push(r.prompt.clone());
            let next = self.replies.lock().unwrap().remove(0);
            next.map(|json| AiResponse { json, model: "m".into(), input_tokens: 1000, output_tokens: 500 })
        }
    }

    fn layer(hosted: Vec<Result<Value, ProviderError>>, local: Vec<Result<Value, ProviderError>>, autonomy: Autonomy) -> (AiLayer, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(vec![]));
        let mut cfg = AiConfig::from_yaml(SPEC_YAML).unwrap();
        cfg.autonomy = autonomy;
        cfg.routing.insert("response_advice".into(), "hosted".into());
        let mut providers: BTreeMap<String, Box<dyn AiProvider>> = BTreeMap::new();
        providers.insert("hosted".into(), Box::new(Scripted { replies: Arc::new(Mutex::new(hosted)), name: "hosted".into(), local: false, seen: seen.clone() }));
        providers.insert("local".into(), Box::new(Scripted { replies: Arc::new(Mutex::new(local)), name: "local".into(), local: true, seen: seen.clone() }));
        let mut l = AiLayer::new(cfg, providers);
        l.activate("hosted", true);
        l.activate("local", true);
        (l, seen)
    }

    fn known() -> BTreeSet<String> {
        ["evd_1".to_string(), "evd_2".to_string()].into_iter().collect()
    }

    #[test]
    fn triage_redacts_cites_and_respects_the_floor() {
        let reply = json!({"alerts": [
            {"id": "a1", "priority": 5, "explanation": "low", "evidence_ids": ["evd_1"]},
            {"id": "a2", "priority": 1, "explanation": "made up", "evidence_ids": ["evd_999"]}
        ]});
        let (mut l, seen) = layer(vec![Ok(reply)], vec![], Autonomy::Advise);
        let floors = [("a1".to_string(), 2u32)].into_iter().collect();
        let r = l.triage(&json!({"alert": "login by bob@corp.example from 198.51.100.4"}), &floors, &known(), 0).unwrap();
        assert_eq!(r.output["alerts"][0]["priority"], 2);
        assert_eq!(r.output["alerts"].as_array().unwrap().len(), 1, "invented finding dropped");
        let prompt = &seen.lock().unwrap()[0];
        assert!(!prompt.contains("bob@corp.example") && !prompt.contains("198.51.100.4"));
        assert!(prompt.contains("<untrusted_evidence>"));
    }

    #[test]
    fn refusal_falls_back_to_vetted_local_and_bad_schema_is_refused() {
        let ok = json!({"actions": [{"action": "ip.ban", "target": "ip:1", "ladder_level": 4, "reason": "r", "reversal": "ip.unban", "evidence_ids": ["evd_1"]}]});
        let (mut l, _) = layer(vec![Err(ProviderError::Refused("cyber".into())), Ok(json!({"actions": [{"oops": 1}]}))], vec![Ok(ok)], Autonomy::Propose);
        let cedar = CedarPolicy::parse(&ivar_core::policy::default_cedar_policies()).unwrap();
        let p = l.advise(&json!({}), &known(), &cedar, "standard", 0).unwrap();
        assert_eq!(p[0].disposition, "needs_approval");
        assert!(matches!(l.advise(&json!({}), &known(), &cedar, "standard", 1), Err(AiError::Schema(_))));
    }

    #[test]
    fn bounded_autonomy_stops_at_level_three() {
        let reply = json!({"actions": [
            {"action": "throttle", "target": "ip:1", "ladder_level": 1, "reason": "r", "reversal": "throttle.lift", "evidence_ids": ["evd_1"]},
            {"action": "session.revoke", "target": "session:s", "ladder_level": 4, "reason": "r", "reversal": "session.restore", "evidence_ids": ["evd_2"]}
        ]});
        let (mut l, _) = layer(vec![Ok(reply)], vec![], Autonomy::Bounded);
        let cedar = CedarPolicy::parse(&ivar_core::policy::default_cedar_policies()).unwrap();
        let p = l.advise(&json!({}), &known(), &cedar, "standard", 0).unwrap();
        assert_eq!(p[0].disposition, "approved_by_policy");
        assert_eq!(p[1].disposition, "needs_approval");
    }

    #[test]
    fn off_unactivated_and_limits() {
        let (mut l, _) = layer(vec![], vec![], Autonomy::Off);
        assert_eq!(l.run(Role::TriageAnalyst, &json!({}), &known(), 0).unwrap_err(), AiError::Off);
        let (mut l, _) = layer(vec![], vec![], Autonomy::Advise);
        l.activate("hosted", false);
        assert!(matches!(l.run(Role::TriageAnalyst, &json!({}), &known(), 0), Err(AiError::NotActivated(_))));
    }

    struct FakeHttp(Value, Arc<Mutex<Option<Value>>>);
    impl HttpTransport for FakeHttp {
        fn post_json(&self, _u: &str, h: &[(&str, String)], body: &Value) -> Result<(u16, Value), String> {
            assert!(h.iter().any(|(k, v)| *k == "anthropic-version" && v == "2026-10-21"));
            assert!(h.iter().any(|(k, v)| *k == "x-api-key" && v == "test-key"));
            *self.1.lock().unwrap() = Some(body.clone());
            Ok((200, self.0.clone()))
        }
    }
    struct Key;
    impl SecretResolver for Key {
        fn resolve(&self, r: &str) -> Option<String> {
            (r == "vault://ivar/ai-key").then(|| "test-key".into())
        }
    }

    #[test]
    fn anthropic_request_and_response_shape() {
        let sent = Arc::new(Mutex::new(None));
        let reply = json!({"model": "claude-opus-5-5", "stop_reason": "end_turn", "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": "{\"alerts\": []}"}], "usage": {"input_tokens": 10, "output_tokens": 5}});
        let p = AnthropicProvider::new("hosted", None, "vault://ivar/ai-key", FakeHttp(reply, sent.clone()), Key);
        let r = p.complete(&AiRequest { system: "s".into(), prompt: "p".into(), schema: Role::TriageAnalyst.schema(), max_tokens: 16_000 }).unwrap();
        assert_eq!(r.json, json!({"alerts": []}));
        let body = sent.lock().unwrap().clone().unwrap();
        assert_eq!(body["model"], "claude-opus-5-5");
        assert_eq!(body["thinking"]["type"], "adaptive");
        assert_eq!(body["output_config"]["format"]["type"], "json_schema");
        assert_eq!(body["fallbacks"], "default");
        let refusal = json!({"stop_reason": "refusal", "stop_details": {"category": "cyber"}, "content": []});
        let p = AnthropicProvider::new("hosted", None, "vault://ivar/ai-key", FakeHttp(refusal, sent), Key);
        assert_eq!(p.complete(&AiRequest { system: "s".into(), prompt: "p".into(), schema: json!({}), max_tokens: 10 }).unwrap_err(), ProviderError::Refused("cyber".into()));
    }
}
