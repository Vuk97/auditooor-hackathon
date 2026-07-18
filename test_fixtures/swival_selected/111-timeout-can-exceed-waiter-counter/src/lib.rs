//! Hermetic Swival fixture skeleton.
//! Boundary: models counter reconciliation only; it is not an executable Xous Condvar proof.

pub mod vulnerable {
    #[derive(Default)]
    pub struct Counters {
        pub counter: usize,
        pub timed_out: usize,
    }

    impl Counters {
        pub fn notify_selected_before_delivery(&mut self) {
            self.counter = self.counter.saturating_sub(1);
        }

        pub fn late_timeout(&mut self) {
            self.timed_out += 1;
        }

        pub fn impossible_state(&self) -> bool {
            self.timed_out > self.counter
        }
    }
}

pub mod clean {
    #[derive(Default)]
    pub struct Counters {
        pub counter: usize,
        pub timed_out: usize,
    }

    impl Counters {
        pub fn reconcile_timeouts(&mut self) {
            self.counter = self.counter.saturating_sub(self.timed_out);
            self.timed_out = 0;
        }

        pub fn confirmed_notify(&mut self, notified: usize) {
            self.counter = self.counter.saturating_sub(notified);
        }

        pub fn impossible_state(&self) -> bool {
            self.timed_out > self.counter
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_can_record_more_timeouts_than_waiters() {
        let mut counters = vulnerable::Counters { counter: 1, timed_out: 0 };
        counters.notify_selected_before_delivery();
        counters.late_timeout();
        assert!(counters.impossible_state());
    }

    #[test]
    fn clean_model_uses_saturating_reconciliation() {
        let mut counters = clean::Counters { counter: 0, timed_out: 1 };
        counters.reconcile_timeouts();
        counters.confirmed_notify(1);
        assert!(!counters.impossible_state());
        assert_eq!(counters.counter, 0);
    }
}
