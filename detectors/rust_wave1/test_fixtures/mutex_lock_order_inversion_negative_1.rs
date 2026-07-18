// NEGATIVE: Both functions acquire locks in the SAME order — no inversion.

use std::sync::{Arc, Mutex};

struct Store {
    primary: Arc<Mutex<u64>>,
    secondary: Arc<Mutex<u64>>,
}

impl Store {
    // acquires: primary -> secondary
    pub fn write_both(&self, a: u64, b: u64) {
        let mut p = self.primary.lock().unwrap();
        let mut s = self.secondary.lock().unwrap();
        *p = a;
        *s = b;
    }

    // acquires: primary -> secondary  (SAME order — no inversion)
    pub fn read_both(&self) -> (u64, u64) {
        let p = self.primary.lock().unwrap();
        let s = self.secondary.lock().unwrap();
        (*p, *s)
    }
}
