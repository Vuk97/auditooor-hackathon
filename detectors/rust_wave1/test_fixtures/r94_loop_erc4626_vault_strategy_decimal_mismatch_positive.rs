use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: strategy takes 6-dec value, vault passes 18-dec amount as-is
    pub fn deposit(assets: u128) -> u128 {
        strategy.deposit(assets);
        assets
    }
}
struct Strategy;
impl Strategy { fn deposit(&self, _a: u128) {} }
#[allow(non_upper_case_globals)]
static strategy: Strategy = Strategy;
