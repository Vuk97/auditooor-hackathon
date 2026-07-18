use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Policy;
#[contractimpl]
impl Policy {
    // BUG: amount hardcoded to 1 instead of order.amount
    pub fn can_match_maker_ask(price: u128, collection: u64, token_id: u64) -> (u128, u64, u64, u128) {
        (price, collection, token_id, 1)
    }
}
