use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: scales 18-dec assets down to strategy's 6-dec before call
    pub fn deposit(assets: u128) -> u128 {
        let scaled = assets / 10u128.pow(12);
        strategy.deposit(scaled);
        assets
    }
}
struct Strategy;
impl Strategy { fn deposit(&self, _a: u128) {} }
#[allow(non_upper_case_globals)]
static strategy: Strategy = Strategy;
