use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeMarginDex;
#[contractimpl]
impl SafeMarginDex {
    // OK: slippage capped at protocol_max before forwarding
    pub fn open_position(collateral: u128, size: u128, slippage: u128) -> u128 {
        require(slippage <= protocol_max());
        vault.swap(collateral, size, slippage);
        size
    }
}
fn require(_c: bool) {}
fn protocol_max() -> u128 { 500 }
struct Vault;
impl Vault { fn swap(&self, _c: u128, _s: u128, _sl: u128) {} }
#[allow(non_upper_case_globals)]
static vault: Vault = Vault;
