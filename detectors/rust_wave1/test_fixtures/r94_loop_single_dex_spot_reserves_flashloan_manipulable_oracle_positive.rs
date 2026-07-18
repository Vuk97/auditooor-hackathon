use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Pair;
impl Pair {
    fn get_reserves(&self) -> (u128, u128) { (1_000_000, 2_000_000) }
}
#[contract]
pub struct PriceProvider;
#[contractimpl]
impl PriceProvider {
    // BUG: price from instantaneous get_reserves, no TWAP
    pub fn get_token_price(pair: Pair) -> u128 {
        let (r0, r1) = pair.get_reserves();
        r1 * 1_000_000_000_000_000_000 / r0
    }
}
