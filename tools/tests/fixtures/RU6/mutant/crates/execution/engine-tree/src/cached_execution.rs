// Mutant: idempotent cache-load swapped for an ORDER-DEPENDENT Vec-push over
// the same HashMap iteration -> fires (behavior-changing mutation-kill).
use std::collections::HashMap;

struct Exec;

impl Exec {
    fn execute_transaction_without_commit(&mut self, cached: &Cached) -> Result<(), Err> {
        let tx_hash = self.tx().tx_hash();
        let prev_tx_hash = self.prev();
        let mut ordered_addrs = Vec::new();
        for address in cached.state.keys() {
            ordered_addrs.push(*address);
        }
        Ok(())
    }
}

struct Cached { state: HashMap<u64, u64> }
