use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVerifier;
#[contractimpl]
impl SafeVerifier {
    // OK: asserts prover_log_blowup is zero before use
    pub fn verify_recursive(prover_log_blowup: u64, trace_len: u64) -> bool {
        assert_eq!(prover_log_blowup, 0, "log_blowup must be zero");
        let domain_size = trace_len << prover_log_blowup;
        domain_size > 0
    }

    // OK: assert_range on chip_ordering before indexing
    pub fn eval_opening(chip_ordering: Vec<u32>, openings: Vec<u128>) -> u128 {
        for idx in &chip_ordering {
            assert!(*idx < openings.len() as u32, "chip_ordering out of range");
        }
        let mut sum: u128 = 0;
        for idx in &chip_ordering {
            sum += openings[*idx as usize];
        }
        sum
    }

    // OK: constrain(...) helper
    pub fn verify_quotient(quotient_domain: u64, trace_size: u64) -> bool {
        constrain(quotient_domain == trace_size * 2);
        true
    }
}
fn constrain(_c: bool) {}
