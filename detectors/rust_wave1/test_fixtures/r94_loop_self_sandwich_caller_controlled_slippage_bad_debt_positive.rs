use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct MarginDex;
#[contractimpl]
impl MarginDex {
    // BUG: slippage is caller-controlled, uncapped, forwarded to vault.swap
    pub fn open_position(collateral: u128, size: u128, slippage: u128) -> u128 {
        vault.swap(collateral, size, slippage);
        size
    }
}
struct Vault;
impl Vault { fn swap(&self, _c: u128, _s: u128, _sl: u128) {} }
#[allow(non_upper_case_globals)]
static vault: Vault = Vault;
