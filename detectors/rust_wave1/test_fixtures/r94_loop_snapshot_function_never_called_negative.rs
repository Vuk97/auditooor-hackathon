// OK: exposes take_snapshot which calls _snapshot()
use openzeppelin::token::erc20::extensions::ERC20Snapshot;
use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeToken;
#[contractimpl]
impl SafeToken {
    pub fn take_snapshot() -> u64 {
        _snapshot()
    }
    pub fn balance_of_at(user: u64, snapshot_id: u64) -> u128 {
        let _ = (user, snapshot_id);
        0
    }
}
fn _snapshot() -> u64 { 0 }
