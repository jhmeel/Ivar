//! Flow table: bytes per five tuple, bounded, oldest evicted.

use crate::packet::Packet;
use std::collections::{BTreeMap, VecDeque};

type Key = (String, String, u8, u16, u16);

pub struct FlowTable {
    flows: BTreeMap<Key, (u64, i64)>,
    order: VecDeque<Key>,
    cap: usize,
}

impl FlowTable {
    pub fn new(cap: usize) -> Self {
        FlowTable { flows: BTreeMap::new(), order: VecDeque::new(), cap }
    }

    /// Returns true for the first packet of a flow.
    pub fn record(&mut self, p: &Packet, now: i64) -> bool {
        let k = (p.src.clone(), p.dst.clone(), p.proto, p.src_port, p.dst_port);
        if let Some(f) = self.flows.get_mut(&k) {
            f.0 += p.len as u64;
            f.1 = now;
            return false;
        }
        self.flows.insert(k.clone(), (p.len as u64, now));
        self.order.push_back(k);
        if self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.flows.remove(&old);
            }
        }
        true
    }

    pub fn bytes(&self, src: &str, dst: &str) -> u64 {
        self.flows.iter().filter(|(k, _)| k.0 == src && k.1 == dst).map(|(_, v)| v.0).sum()
    }
}
