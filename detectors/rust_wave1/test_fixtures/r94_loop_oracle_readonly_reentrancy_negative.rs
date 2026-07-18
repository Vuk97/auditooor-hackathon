use soroban_sdk::{contract, contractimpl};
pub struct BalancerVault;
impl BalancerVault { pub fn get_pool_tokens(&self, _id: u64) -> (u128, u128) { (0, 0) } }
#[contract]
pub struct SafeOracle;
#[contractimpl]
impl SafeOracle {
    // OK: checkNotInVaultContext before reading pool state
    pub fn get_price(balancer_vault: BalancerVault, id: u64) -> u128 {
        check_not_in_vault_context();
        let (a, b) = balancer_vault.get_pool_tokens(id);
        a + b
    }
}
fn check_not_in_vault_context() {}
