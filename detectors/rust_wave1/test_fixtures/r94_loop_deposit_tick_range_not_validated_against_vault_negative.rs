use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: require tick_lower == vault.tick_lower && tick_upper == vault.tick_upper
    pub fn deposit_fixed(tick_lower: i32, tick_upper: i32, amount: u128, vault: VaultState) -> u128 {
        require(tick_lower == vault.tick_lower);
        require(tick_upper == vault.tick_upper);
        provide_liquidity(tick_lower, tick_upper, amount)
    }
}
pub struct VaultState { pub tick_lower: i32, pub tick_upper: i32 }
fn require(_c: bool) {}
fn provide_liquidity(_l: i32, _u: i32, _a: u128) -> u128 { 0 }
