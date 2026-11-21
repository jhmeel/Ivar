//! Fail open budget (FAIL_OPEN_BUDGET_PCT, default 0.1): the share of
//! requests per route that may pass uninspected before the route is throttled.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOpenDecision {
    /// Pass uninspected; flagged for asynchronous re inspection.
    PassAndReinspect,
    /// Budget exceeded: throttle the route to a safe rate and page on call.
    ThrottleAndPage,
    /// Admin routes never fail open.
    FailClosed,
}

#[derive(Debug, Clone, Default)]
struct RouteCounters {
    total: u64,
    uninspected: u64,
}

#[derive(Debug, Clone)]
pub struct FailOpenBudget {
    pct: f64,
    /// Requests seen before the percentage applies, so one early timeout is not a breach.
    min_sample: u64,
    routes: BTreeMap<String, RouteCounters>,
    reinspect: Vec<String>,
}

impl FailOpenBudget {
    pub fn new(pct: f64) -> Self {
        FailOpenBudget { pct, min_sample: 1000, routes: BTreeMap::new(), reinspect: Vec::new() }
    }

    pub fn with_min_sample(mut self, n: u64) -> Self {
        self.min_sample = n;
        self
    }

    /// Count an inspected request.
    pub fn inspected(&mut self, route: &str) {
        self.routes.entry(route.into()).or_default().total += 1;
    }

    /// The filter crashed or timed out on this request.
    pub fn failed(&mut self, route: &str, request_id: &str, admin: bool) -> FailOpenDecision {
        if admin {
            return FailOpenDecision::FailClosed;
        }
        let c = self.routes.entry(route.into()).or_default();
        c.total += 1;
        let allowed = ((c.total.max(self.min_sample) as f64) * self.pct / 100.0).floor() as u64;
        if c.uninspected + 1 > allowed.max(1) {
            return FailOpenDecision::ThrottleAndPage;
        }
        c.uninspected += 1;
        self.reinspect.push(request_id.into());
        FailOpenDecision::PassAndReinspect
    }

    /// Requests to inspect again asynchronously.
    pub fn drain_reinspection(&mut self) -> Vec<String> {
        std::mem::take(&mut self.reinspect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted_timeouts_exhaust_the_budget() {
        let mut b = FailOpenBudget::new(0.1);
        assert_eq!(b.failed("/admin/users", "r0", true), FailOpenDecision::FailClosed);
        assert_eq!(b.failed("/pay", "r1", false), FailOpenDecision::PassAndReinspect);
        assert_eq!(b.failed("/pay", "r2", false), FailOpenDecision::ThrottleAndPage);
        for _ in 0..3000 {
            b.inspected("/pay");
        }
        assert_eq!(b.failed("/pay", "r3", false), FailOpenDecision::PassAndReinspect);
        assert_eq!(b.drain_reinspection(), vec!["r1", "r3"]);
    }
}
