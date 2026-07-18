// Uses ERC20Snapshot but never calls _snapshot()
use openzeppelin::token::erc20::extensions::ERC20Snapshot;
use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Token;
#[contractimpl]
impl Token {
    pub fn balance_of_at(user: u64, snapshot_id: u64) -> u128 {
        let _ = (user, snapshot_id);
        0
    }
}
