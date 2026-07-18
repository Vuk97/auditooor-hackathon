use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeHub;
#[contractimpl]
impl SafeHub {
    // OK: does not invoke caller hook (only internal swap path)
    pub fn swap(amount: u128) -> u128 {
        non_reentrant();
        let out = pool_manager.swap(amount);
        out
    }
}
fn non_reentrant() {}
struct PoolManager;
impl PoolManager { fn swap(&self, _a: u128) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static pool_manager: PoolManager = PoolManager;
