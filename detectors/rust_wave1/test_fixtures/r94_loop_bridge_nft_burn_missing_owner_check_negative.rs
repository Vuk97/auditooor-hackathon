use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn burn_nft(_token_id: u64) {}
fn owner_of(_token_id: u64) -> Address { [0; 20] }
fn pay_bridge(_who: Address, _amount: u64) {}
#[contract]
pub struct JackpotBridgeManager;
#[contractimpl]
impl JackpotBridgeManager {
    // SAFE: asserts owner_of(token_id) == caller before burning
    pub fn bridge_out(caller: Address, token_id: u64, amount: u64) {
        assert!(owner_of(token_id) == caller, "caller is not ticket owner");
        burn_nft(token_id);
        pay_bridge(caller, amount);
    }
}
