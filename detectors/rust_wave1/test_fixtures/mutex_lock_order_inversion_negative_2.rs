// NEGATIVE: Only one lock used in each function — no ordering to invert.

use std::sync::{Arc, Mutex};

struct SingleLock {
    counter: Arc<Mutex<u64>>,
}

impl SingleLock {
    pub fn increment(&self) {
        let mut c = self.counter.lock().unwrap();
        *c += 1;
    }

    pub fn reset(&self) {
        let mut c = self.counter.lock().unwrap();
        *c = 0;
    }
}
