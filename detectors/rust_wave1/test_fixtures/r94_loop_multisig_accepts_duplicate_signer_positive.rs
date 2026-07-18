use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct MultiSig;
#[contractimpl]
impl MultiSig {
    // BUG: iterates sigs and counts without dedup by signer
    pub fn validate_message(msg: u128, sigs: &[u128]) -> bool {
        let _ = msg;
        let mut count = 0u32;
        for sig in sigs {
            let _ = sig;
            count += 1;
        }
        count >= 3
    }
}
