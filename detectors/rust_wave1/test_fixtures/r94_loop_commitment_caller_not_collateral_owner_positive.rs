use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: caller == strategist OR verify_signature — but never caller == collateral_owner
    pub fn validate_commitment(caller: u64, strategist: u64, sig: u128) -> bool {
        if caller == strategist || verify_signature(sig) {
            return true;
        }
        false
    }
}
fn verify_signature(_s: u128) -> bool { false }
