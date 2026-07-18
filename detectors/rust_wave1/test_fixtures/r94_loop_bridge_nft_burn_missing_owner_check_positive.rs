use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn burn_nft(_token_id: u64) {}
fn pay_bridge(_who: Address, _amount: u64) {}
#[contract]
pub struct JackpotBridgeManager;
#[contractimpl]
impl JackpotBridgeManager {
    // BUG: burns ticket NFT without asserting caller owns it
    pub fn bridge_out(caller: Address, token_id: u64, amount: u64) {
        burn_nft(token_id);
        pay_bridge(caller, amount);
    }
}
