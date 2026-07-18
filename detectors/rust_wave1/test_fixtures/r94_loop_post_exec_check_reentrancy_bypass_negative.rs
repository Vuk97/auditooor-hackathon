use soroban_sdk::{contract, contractimpl};
pub struct Safe;
impl Safe {
    pub fn get_modules(&self) -> Vec<u64> { vec![] }
    pub fn execute(&self, _tx: u64) {}
}
#[contract]
pub struct SafeGuard;
#[contractimpl]
impl SafeGuard {
    // OK: non_reentrant guard
    pub fn check_after_execution(safe: Safe, tx: u64) -> bool {
        non_reentrant();
        let modules_before = safe.get_modules();
        safe.execute(tx);
        let modules_after = safe.get_modules();
        modules_before == modules_after
    }
}
fn non_reentrant() {}
