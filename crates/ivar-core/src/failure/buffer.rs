//! Event buffer: while the core is unreachable, sensors keep enforcing their
//! last signed policy and buffer events, dropping the oldest when full and
//! counting what was dropped (a gap the replay will show).

use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct EventBuffer<T> {
    items: VecDeque<T>,
    capacity: usize,
    pub dropped: u64,
}

impl<T> EventBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        EventBuffer { items: VecDeque::new(), capacity: capacity.max(1), dropped: 0 }
    }

    pub fn push(&mut self, item: T) {
        if self.items.len() == self.capacity {
            self.items.pop_front();
            self.dropped += 1;
        }
        self.items.push_back(item);
    }

    pub fn drain(&mut self) -> Vec<T> {
        self.items.drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
