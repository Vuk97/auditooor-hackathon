use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Verifier;
#[contractimpl]
impl Verifier {
    // BUG: prover_log_blowup read + used in arithmetic with no constraint.
    pub fn verify_recursive(prover_log_blowup: u64, trace_len: u64) -> bool {
        let domain_size = trace_len << prover_log_blowup;
        domain_size > 0
    }

    // BUG: chip_ordering used to index without assert_range
    pub fn eval_opening(chip_ordering: Vec<u32>, openings: Vec<u128>) -> u128 {
        let mut sum: u128 = 0;
        for idx in &chip_ordering {
            sum += openings[*idx as usize];
        }
        sum
    }
}
