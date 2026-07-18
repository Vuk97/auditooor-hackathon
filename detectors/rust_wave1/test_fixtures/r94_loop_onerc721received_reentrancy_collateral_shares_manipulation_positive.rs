use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;
type Address = [u8; 20];
pub struct Collateral { collateral_shares: HashMap<u64, u64> }
fn load_collateral() -> Collateral { Collateral { collateral_shares: HashMap::new() } }
fn save_collateral(_c: &Collateral) {}
fn safe_transfer_from(_token: Address, _from: Address, _to: Address, _token_id: u64) {}
#[contract]
pub struct V3Vault;
#[contractimpl]
impl V3Vault {
    // BUG: mutates collateral_shares and then calls safe_transfer_from — reentrancy path
    pub fn on_erc721_received(operator: Address, from: Address, token_id: u64, data: Vec<u8>) -> bool {
        let mut c = load_collateral();
        c.collateral_shares.insert(token_id, 1000);
        // External call before state is committed
        safe_transfer_from(operator, from, [0; 20], token_id);
        save_collateral(&c);
        true
    }
}
