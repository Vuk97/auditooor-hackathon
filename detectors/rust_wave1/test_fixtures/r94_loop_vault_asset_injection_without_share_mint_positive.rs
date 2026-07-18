use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: mints DUSD debt directly to vault address without minting shares
    pub fn distribute_reward(amount: u128) {
        dusd.mint(vault_address(), amount);
    }
}
fn vault_address() -> u64 { 0 }
struct Dusd;
impl Dusd { fn mint(&self, _to: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static dusd: Dusd = Dusd;
