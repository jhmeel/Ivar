//! The chain each high consequence action must carry (section 6.2 table).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentChain {
    pub action: &'static str,
    /// Ordered steps; the first is the origin that mints the token.
    pub steps: &'static [&'static str],
    pub checked_at: &'static str,
}

pub const CHAINS: &[IntentChain] = &[
    IntentChain { action: "payout", steps: &["customer_request", "authenticated_session", "ledger_entry", "payout_instruction"], checked_at: "payout service or signer" },
    IntentChain { action: "signing", steps: &["customer_request", "authenticated_session", "ledger_entry", "signing_request"], checked_at: "signer" },
    IntentChain { action: "deploy", steps: &["reviewed_commit", "approved_change", "build_provenance", "deploy"], checked_at: "deploy controller" },
    IntentChain { action: "role_grant", steps: &["admin_request", "second_approver", "grant"], checked_at: "application SDK and identity connector" },
    IntentChain { action: "bulk_export", steps: &["business_task", "owner_approval", "export_job"], checked_at: "database sensor or export API" },
    IntentChain { action: "agent_action", steps: &["human_delegation", "task_scope", "tool_call"], checked_at: "AI gateway sensor" },
];

pub fn chain_for(action: &str) -> Option<&'static IntentChain> {
    CHAINS.iter().find(|c| c.action == action)
}
