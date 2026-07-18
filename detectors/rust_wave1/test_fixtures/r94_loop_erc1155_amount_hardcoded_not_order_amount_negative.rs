use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePolicy;
#[contractimpl]
impl SafePolicy {
    // OK: uses order.amount instead of hardcoded 1
    pub fn can_match_maker_ask(price: u128, collection: u64, token_id: u64, order: Order) -> (u128, u64, u64, u128) {
        (price, collection, token_id, order.amount)
    }
}
pub struct Order { pub amount: u128 }
