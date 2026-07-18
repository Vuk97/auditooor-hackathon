use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn price(_token: Address) -> u128 { 1_000_000 }
fn balance_a(_pool: Address) -> u128 { 100_000 }
fn balance_b(_pool: Address) -> u128 { 200_000 }
fn isqrt(x: u128) -> u128 { let mut r = 0; while r * r <= x { r += 1 } r - 1 }
fn total_supply(_pool: Address) -> u128 { 1000 }
#[contract]
pub struct LpOracle;
#[contractimpl]
impl LpOracle {
    // SAFE: fair_lp (Alpha Homora) price = 2*sqrt(reserveA*reserveB*priceA*priceB) / totalSupply
    pub fn lp_price(pool: Address, token_a: Address, token_b: Address) -> u128 {
        let balanceA = balance_a(pool);
        let balanceB = balance_b(pool);
        let priceA = price(token_a);
        let priceB = price(token_b);
        let k = balanceA * balanceB;
        let fairLp = 2 * isqrt(k * priceA * priceB);
        fairLp / total_supply(pool)
    }
}
