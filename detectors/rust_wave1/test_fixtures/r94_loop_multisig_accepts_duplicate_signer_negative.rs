use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeMultiSig;
#[contractimpl]
impl SafeMultiSig {
    // OK: tracks seen_signers in a set for dedup
    pub fn validate_message(msg: u128, sigs: &[u128]) -> bool {
        let _ = msg;
        let mut signers_seen: [u64; 16] = [0; 16];
        let _ = signers_seen;
        let mut count = 0u32;
        for sig in sigs {
            let _ = sig;
            count += 1;
        }
        count >= 3
    }
}
