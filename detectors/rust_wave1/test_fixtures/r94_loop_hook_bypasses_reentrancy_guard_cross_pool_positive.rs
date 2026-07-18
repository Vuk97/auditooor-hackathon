use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Hub;
#[contractimpl]
impl Hub {
    // BUG: has non_reentrant, invokes hook, and calls pool_manager directly
    pub fn swap(hook: Hook, amount: u128) -> u128 {
        non_reentrant();
        hook.before_swap(amount);
        let out = pool_manager.swap(amount);
        out
    }
}
fn non_reentrant() {}
pub struct Hook;
impl Hook { fn before_swap(&self, _a: u128) {} }
struct PoolManager;
impl PoolManager { fn swap(&self, _a: u128) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static pool_manager: PoolManager = PoolManager;
