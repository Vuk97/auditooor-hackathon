// POSITIVE: RwLock order inversion in coordinator.
// fn process() acquires `state` (write) then `cache` (read).
// fn flush() acquires `cache` (write) then `state` (read).

use parking_lot::RwLock;
use std::sync::Arc;

struct Coordinator {
    state: Arc<RwLock<u64>>,
    cache: Arc<RwLock<Vec<u8>>>,
}

impl Coordinator {
    // acquires: state -> cache
    pub fn process(&self, val: u64) {
        let mut state = self.state.write();
        *state = val;
        let cache = self.cache.read();
        println!("cache size: {}", cache.len());
    }

    // acquires: cache -> state  (INVERTED!)
    pub fn flush(&self) {
        let mut cache = self.cache.write();
        cache.clear();
        let state = self.state.read();
        println!("state after flush: {}", *state);
    }
}
