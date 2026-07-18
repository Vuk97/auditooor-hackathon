use soroban_sdk::{contract, contractimpl};
pub struct Validator { pub effective_balance: u64 }
#[contract]
pub struct Beacon;
#[contractimpl]
impl Beacon {
    // BUG: computes proposer via effective_balance + compute_shuffled_index, no lookahead cache
    pub fn get_beacon_proposer_indices(validators: Vec<Validator>, slot: u64) -> usize {
        let total: u64 = validators.iter().map(|v| v.effective_balance).sum();
        let idx = compute_shuffled_index(slot, total);
        idx
    }
}
fn compute_shuffled_index(_slot: u64, _total: u64) -> usize { 0 }
