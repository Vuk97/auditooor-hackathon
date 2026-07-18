use soroban_sdk::{contract, contractimpl};
pub struct BalancerVault;
impl BalancerVault { pub fn get_pool_tokens(&self, _id: u64) -> (u128, u128) { (0, 0) } }
#[contract]
pub struct Oracle;
#[contractimpl]
impl Oracle {
    // BUG: reads balancer_vault.get_pool_tokens without reentrancy guard
    pub fn get_price(balancer_vault: BalancerVault, id: u64) -> u128 {
        let (a, b) = balancer_vault.get_pool_tokens(id);
        a + b
    }
}
