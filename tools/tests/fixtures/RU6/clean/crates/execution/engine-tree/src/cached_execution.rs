// Distilled negative control from base-azul cached_execution.rs:192.
// Iterates state.keys() but performs only an idempotent cache-load -> no
// ORDER-DEPENDENT sink -> MUST NOT fire (the FP-guard teeth).
use std::collections::HashMap;

struct Exec;

impl Exec {
    fn execute_transaction_without_commit(&mut self, cached: &Cached) -> Result<(), Err> {
        let tx_hash = self.tx().tx_hash();
        let prev_tx_hash = self.prev();
        for address in cached.state.keys() {
            // ignore the result: we don't care if the account exists or not
            self.db_mut().load_cache_account(*address)?;
        }
        Ok(())
    }
}

struct Cached { state: HashMap<u64, u64> }
