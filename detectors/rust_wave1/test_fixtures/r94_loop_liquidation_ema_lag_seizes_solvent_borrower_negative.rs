use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeEngine;
#[contractimpl]
impl SafeEngine {
    // OK: cross-checks ema against spot_price before liquidating
    pub fn is_liquidatable(collateral: u128, debt: u128) -> bool {
        let ema = ema_price();
        let spot = spot_price();
        let _ = spot;
        if ema < spot { return false; }
        let value = collateral * ema / 1_000_000;
        value < debt
    }
}
fn ema_price() -> u128 { 0 }
fn spot_price() -> u128 { 0 }
