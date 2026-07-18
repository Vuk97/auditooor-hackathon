use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn eigenlayer_stake(_credentials: Address, _amount: u64) {}
fn save_withdraw_credentials(_v: u64, _c: Address) {}
#[contract]
pub struct NodeDelegator;
#[contractimpl]
impl NodeDelegator {
    // BUG: operator supplies withdraw_credentials, no auth / invariant check
    pub fn stake(validator_id: u64, withdraw_credentials: Address, amount: u64) {
        save_withdraw_credentials(validator_id, withdraw_credentials);
        eigenlayer_stake(withdraw_credentials, amount);
    }
}
