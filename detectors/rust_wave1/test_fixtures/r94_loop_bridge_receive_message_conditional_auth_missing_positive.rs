use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Asset;
#[contractimpl]
impl Asset {
    // BUG: require_auth only runs when threshold == 1
    pub fn receive_message(transfer: Transfer, amount: u128) {
        if transfer.threshold == 1 {
            require_auth(transfer.sender);
        }
        apply(transfer, amount);
    }
}
pub struct Transfer { pub threshold: u64, pub sender: u64 }
fn require_auth(_s: u64) {}
fn apply(_t: Transfer, _a: u128) {}
