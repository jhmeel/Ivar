//! The verdict feed: every enforcement point learns the core's standing
//! verdicts, not only the sensor whose event produced them.
//!
//! An edge gateway runs one filter instance per worker thread and an
//! application may never see the request that got an attacker contained, so
//! a verdict returned only to the sensor that reported the event leaves the
//! other enforcement points open. Each sensor keeps a cursor, sends it with
//! its batches (or polls when idle) and receives everything since.

use ivar_contracts::Verdict;
use std::collections::VecDeque;

/// Decisions that apply to an entity's later requests.
const STANDING: &[&str] = &["contain", "throttle", "challenge"];

pub struct VerdictFeed {
    entries: VecDeque<(u64, Verdict)>,
    next: u64,
    cap: usize,
}

impl Default for VerdictFeed {
    fn default() -> Self {
        VerdictFeed { entries: VecDeque::new(), next: 1, cap: 50_000 }
    }
}

impl VerdictFeed {
    pub fn with_capacity(cap: usize) -> Self {
        VerdictFeed { cap, ..Default::default() }
    }

    /// Record a verdict if it stands beyond the request that produced it.
    pub fn push(&mut self, v: &Verdict) {
        if !STANDING.contains(&v.decision.as_str()) {
            return;
        }
        if self.entries.len() >= self.cap {
            self.entries.pop_front();
        }
        self.entries.push_back((self.next, v.clone()));
        self.next += 1;
    }

    /// The cursor a sensor sends next time.
    pub fn cursor(&self) -> u64 {
        self.next - 1
    }

    /// Standing verdicts recorded after `cursor` that have not expired. A
    /// cursor of 0 (a sensor that just started) returns every one still in
    /// force, so a new gateway worker enforces existing containments at once.
    pub fn since(&self, cursor: u64, now: i64) -> Vec<Verdict> {
        self.entries
            .iter()
            .filter(|(seq, v)| *seq > cursor && (v.expires_at > now || (v.expires_at == 0 && v.decision == "contain")))
            .map(|(_, v)| v.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(id: &str, decision: &str, expires_at: i64) -> Verdict {
        Verdict { verdict_id: id.into(), decision: decision.into(), expires_at, mode: "enforce".into(), ..Default::default() }
    }

    #[test]
    fn standing_verdicts_reach_every_cursor() {
        let mut f = VerdictFeed::default();
        f.push(&v("a", "block", 0));
        f.push(&v("b", "contain", 10_000));
        f.push(&v("c", "throttle", 50));
        let c = f.cursor();
        f.push(&v("d", "challenge", 10_000));
        assert_eq!(f.since(0, 100).iter().map(|x| x.verdict_id.as_str()).collect::<Vec<_>>(), vec!["b", "d"], "per request blocks and expired throttles are not standing");
        assert_eq!(f.since(c, 100).iter().map(|x| x.verdict_id.as_str()).collect::<Vec<_>>(), vec!["d"]);
        assert!(f.since(f.cursor(), 100).is_empty());
    }

    #[test]
    fn the_feed_is_bounded() {
        let mut f = VerdictFeed::with_capacity(3);
        for i in 0..10 {
            f.push(&v(&format!("v{i}"), "contain", 0));
        }
        assert_eq!(f.since(0, 0).len(), 3);
        assert_eq!(f.cursor(), 10);
    }
}
