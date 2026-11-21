//! Approvals and alerts for people: Slack, PagerDuty and Jira. Messages carry
//! links for two person approval and time lock cancellation; the decision
//! itself is taken through the authorised API, never inside the chat tool.

use super::{http, Outbound, Sink};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraConfig {
    pub base_url: String,
    pub project_key: String,
    pub user_env: String,
    pub token_env: String,
}

pub struct Notifier {
    slack: Option<String>,
    pagerduty: Option<String>,
    jira: Option<JiraConfig>,
    client: reqwest::blocking::Client,
}

impl Notifier {
    pub fn new(slack: Option<String>, pagerduty: Option<String>, jira: Option<JiraConfig>) -> Self {
        Notifier { slack, pagerduty, jira, client: http() }
    }

    pub fn text(item: &Outbound) -> Option<(String, &'static str)> {
        Some(match item {
            Outbound::ApprovalNeeded { action_request, approve_url } => (
                format!(
                    "Approval needed: {} on {} (ladder level {}). Approve: {approve_url}",
                    action_request.get("action").and_then(|v| v.as_str()).unwrap_or(""),
                    action_request.pointer("/target/id").and_then(|v| v.as_str()).unwrap_or(""),
                    action_request.get("ladder_level").and_then(|v| v.as_u64()).unwrap_or(0)
                ),
                "critical",
            ),
            Outbound::TimeLock { lock, cancel_url } => (
                format!(
                    "Time lock: {} of {} held until {}. Any owner can cancel: {cancel_url}",
                    lock.get("action").and_then(|v| v.as_str()).unwrap_or(""),
                    lock.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    lock.get("release_at").and_then(|v| v.as_i64()).unwrap_or(0)
                ),
                "warning",
            ),
            Outbound::Incident { incident } => (format!("Incident opened: {}", incident.get("title").and_then(|v| v.as_str()).unwrap_or("")), "error"),
            Outbound::Alert { kind, message } => (format!("{kind}: {message}"), "warning"),
            _ => return None,
        })
    }
}

impl Sink for Notifier {
    fn name(&self) -> &str {
        "notify"
    }
    fn send(&mut self, item: &Outbound) -> Result<(), String> {
        let Some((text, severity)) = Self::text(item) else { return Ok(()) };
        if let Some(url) = &self.slack {
            self.client.post(url).json(&json!({ "text": text })).send().map_err(|e| e.to_string())?;
        }
        if let Some(key) = &self.pagerduty {
            if severity == "critical" || severity == "error" {
                let body = json!({ "routing_key": key, "event_action": "trigger", "payload": { "summary": text, "source": "ivar-core", "severity": severity } });
                self.client.post("https://events.pagerduty.com/v2/enqueue").json(&body).send().map_err(|e| e.to_string())?;
            }
        }
        if let Some(j) = &self.jira {
            if matches!(item, Outbound::Incident { .. } | Outbound::ApprovalNeeded { .. }) {
                let user = std::env::var(&j.user_env).map_err(|_| format!("{} not set", j.user_env))?;
                let token = std::env::var(&j.token_env).map_err(|_| format!("{} not set", j.token_env))?;
                let body = json!({ "fields": { "project": { "key": j.project_key }, "summary": text.chars().take(250).collect::<String>(), "issuetype": { "name": "Task" } } });
                self.client.post(format!("{}/rest/api/2/issue", j.base_url.trim_end_matches('/'))).basic_auth(user, Some(token)).json(&body).send().map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }
}
