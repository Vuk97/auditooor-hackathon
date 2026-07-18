use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Market;
#[contractimpl]
impl Market {
    // BUG: funding rate from single maker's skew, applied whole market
    pub fn update_funding() {
        let skew = oracle_maker.skew();
        let rate = skew / 100;
        for pos in positions() {
            apply_funding(pos, rate);
        }
    }
}
struct OracleMaker;
impl OracleMaker { fn skew(&self) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static oracle_maker: OracleMaker = OracleMaker;
fn positions() -> Vec<u64> { Vec::new() }
fn apply_funding(_p: u64, _r: u128) {}
