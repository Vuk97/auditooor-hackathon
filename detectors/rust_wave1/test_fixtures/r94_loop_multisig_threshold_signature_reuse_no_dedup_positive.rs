use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct MultiSig;
#[contractimpl]
impl MultiSig {
    // BUG: signed_data_execution loops sigs, increments acquired_threshold, no dedup
    pub fn signed_data_execution(sigs: &[u128]) -> bool {
        let mut acquired_threshold = 0u32;
        for sig in sigs {
            let _ = sig;
            acquired_threshold += 1;
        }
        acquired_threshold >= 3
    }
}
