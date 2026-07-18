use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeAsset;
#[contractimpl]
impl SafeAsset {
    // OK: require_auth is unconditional, first statement
    pub fn receive_message(transfer: Transfer, amount: u128) {
        require_auth(transfer.sender);
        if transfer.threshold == 1 {
            extra_check(transfer.sender);
        }
        apply(transfer, amount);
    }
}
pub struct Transfer { pub threshold: u64, pub sender: u64 }
fn require_auth(_s: u64) {}
fn extra_check(_s: u64) {}
fn apply(_t: Transfer, _a: u128) {}
