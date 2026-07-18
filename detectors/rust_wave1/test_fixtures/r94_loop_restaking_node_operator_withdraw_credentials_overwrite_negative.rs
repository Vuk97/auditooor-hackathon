use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn eigenlayer_stake(_credentials: Address, _amount: u64) {}
fn save_withdraw_credentials(_v: u64, _c: Address) {}
fn load_current_credentials(_v: u64) -> Address { [0; 20] }
pub struct Env;
fn require_auth(_a: &Address) {}
#[contract]
pub struct NodeDelegator;
#[contractimpl]
impl NodeDelegator {
    // SAFE: only-admin auth + invariant that existing withdraw_credentials is zero
    pub fn stake(admin: Address, validator_id: u64, withdraw_credentials: Address, amount: u64) {
        require_auth(&admin);
        let current_creds = load_current_credentials(validator_id);
        assert!(current_creds == [0u8; 20], "withdrawal_credentials already set");
        save_withdraw_credentials(validator_id, withdraw_credentials);
        eigenlayer_stake(withdraw_credentials, amount);
    }
}
