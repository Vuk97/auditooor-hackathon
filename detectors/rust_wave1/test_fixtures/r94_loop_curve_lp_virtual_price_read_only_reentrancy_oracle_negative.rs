use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct CurvePool { addr: Address }
impl CurvePool {
    fn get_virtual_price(&self) -> u128 { 1_000_000_000_000_000_000 }
    fn remove_liquidity(&self, _amt: u128, _min_amounts: [u128; 2]) {}
}
#[contract]
pub struct StableCurveOracle;
#[contractimpl]
impl StableCurveOracle {
    // SAFE: probes remove_liquidity(0,...) to close read-only reentrancy window
    pub fn get_price(pool: CurvePool) -> u128 {
        pool.remove_liquidity(0, [0, 0]);
        pool.get_virtual_price()
    }
}
