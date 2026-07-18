use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn price(_token: Address) -> u128 { 1_000_000 }
fn balance_a(_pool: Address) -> u128 { 100_000 }
fn balance_b(_pool: Address) -> u128 { 200_000 }
#[contract]
pub struct LpOracle;
#[contractimpl]
impl LpOracle {
    // BUG: prices LP as priceA * balanceA + priceB * balanceB (manipulable)
    pub fn lp_price(pool: Address, token_a: Address, token_b: Address) -> u128 {
        let balanceA = balance_a(pool);
        let balanceB = balance_b(pool);
        let priceA = price(token_a);
        let priceB = price(token_b);
        priceA * balanceA + priceB * balanceB
    }
}
