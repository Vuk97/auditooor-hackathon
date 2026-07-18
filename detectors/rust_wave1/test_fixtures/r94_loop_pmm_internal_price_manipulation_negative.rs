use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: cross-checks against chainlink external_oracle
    pub fn query(base_balance: u128, quote_balance: u128, chainlink_price: u128) -> u128 {
        let internal = quote_balance * 1_000_000 / base_balance;
        let bound = chainlink_price / 10;
        if internal > chainlink_price + bound || internal < chainlink_price - bound {
            return chainlink_price;
        }
        internal
    }
}
