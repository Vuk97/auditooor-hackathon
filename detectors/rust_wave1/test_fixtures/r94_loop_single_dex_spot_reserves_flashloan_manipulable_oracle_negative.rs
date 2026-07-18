use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Pair;
impl Pair {
    fn get_reserves(&self) -> (u128, u128) { (1_000_000, 2_000_000) }
    fn observe(&self, _period: u32) -> u128 { 500_000 }
}
const TWAP_PERIOD: u32 = 1800;
#[contract]
pub struct PriceProvider;
#[contractimpl]
impl PriceProvider {
    // SAFE: uses observe() TWAP over TWAP_PERIOD, not spot reserves
    pub fn get_token_price(pair: Pair) -> u128 {
        let (_r0, _r1) = pair.get_reserves();
        let twap_price = pair.observe(TWAP_PERIOD);
        twap_price
    }
}
