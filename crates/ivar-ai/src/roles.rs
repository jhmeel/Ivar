//! The AI roles (section 12) with their input, output schema and highest autonomy.

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Ranks alerts and groups related findings. Highest autonomy: automatic.
    TriageAnalyst,
    /// Rebuilds attack timelines and scope. Automatic, read only.
    Investigator,
    /// Proposes a playbook (ActionProposal). Approved by policy or a person.
    ResponseAdvisor,
    /// Drafts rules from incidents and advisories. Shadow mode only until reviewed.
    RuleEngineer,
    /// Finds risky settings and missing coverage. Advisory.
    ExposureReviewer,
    /// Selects safe replay tests. Staging only.
    SimulationPlanner,
}

impl Role {
    /// Routing key in the AI configuration.
    pub fn routing_key(self) -> &'static str {
        match self {
            Role::TriageAnalyst => "triage",
            Role::Investigator => "investigation",
            Role::ResponseAdvisor => "response_advice",
            Role::RuleEngineer => "rule_engineering",
            Role::ExposureReviewer => "exposure_review",
            Role::SimulationPlanner => "simulation_planning",
        }
    }

    pub fn task(self) -> &'static str {
        match self {
            Role::TriageAnalyst => "Rank the alerts by priority and group related findings. Explain each priority briefly.",
            Role::Investigator => "Rebuild the attack timeline and its scope from the incident evidence. List affected entities and open questions.",
            Role::ResponseAdvisor => "Propose a playbook of response actions within the given policy limits. Prefer the mildest action on the response ladder that stops the threat, and say how each action is reversed.",
            Role::RuleEngineer => "Draft a detection rule from the threat report and replay results. The rule will run in shadow mode until a person reviews it.",
            Role::ExposureReviewer => "Find risky settings and missing sensor coverage in the configuration and inventory, ranked by risk.",
            Role::SimulationPlanner => "Select safe tests from the attack replay library for staging.",
        }
    }

    pub fn schema(self) -> Value {
        let citations = json!({ "type": "array", "items": { "type": "string" }, "maxItems": 50 });
        let item = |props: Value, required: Vec<&str>| {
            let mut p = props;
            p["evidence_ids"] = citations.clone();
            json!({ "type": "object", "additionalProperties": false, "properties": p, "required": required.into_iter().chain(["evidence_ids"]).collect::<Vec<_>>() })
        };
        let list = |name: &str, it: Value| json!({ "type": "object", "additionalProperties": false, "properties": { name: { "type": "array", "items": it, "maxItems": 100 } }, "required": [name] });
        match self {
            Role::TriageAnalyst => list("alerts", item(json!({ "id": { "type": "string" }, "priority": { "type": "integer", "minimum": 1, "maximum": 5 }, "group": { "type": "string" }, "explanation": { "type": "string", "maxLength": 1000 } }), vec!["id", "priority", "explanation"])),
            Role::Investigator => list("timeline", item(json!({ "time": { "type": "integer" }, "step": { "type": "string", "maxLength": 500 }, "entities": { "type": "array", "items": { "type": "string" } }, "open_question": { "type": "string", "maxLength": 500 } }), vec!["time", "step"])),
            Role::ResponseAdvisor => list("actions", item(json!({ "action": { "type": "string" }, "target": { "type": "string" }, "ladder_level": { "type": "integer", "minimum": 0, "maximum": 6 }, "reason": { "type": "string", "maxLength": 1000 }, "reversal": { "type": "string" } }), vec!["action", "target", "ladder_level", "reason", "reversal"])),
            Role::RuleEngineer => list("rules", item(json!({ "rule_id": { "type": "string" }, "family": { "type": "string" }, "method": { "type": "string", "enum": ["signatures", "positive_security", "behaviour_baselines", "sequence_correlation", "deception", "declared_intent_drift", "consequence_invariants"] }, "description": { "type": "string", "maxLength": 2000 }, "params": { "type": "string", "maxLength": 4000 } }), vec!["rule_id", "family", "method", "description"])),
            Role::ExposureReviewer => list("findings", item(json!({ "setting": { "type": "string" }, "risk": { "type": "integer", "minimum": 1, "maximum": 5 }, "fix": { "type": "string", "maxLength": 1000 } }), vec!["setting", "risk", "fix"])),
            Role::SimulationPlanner => list("tests", item(json!({ "scenario": { "type": "string" }, "environment": { "type": "string", "enum": ["staging"] }, "reason": { "type": "string", "maxLength": 500 } }), vec!["scenario", "environment", "reason"])),
        }
    }
}
