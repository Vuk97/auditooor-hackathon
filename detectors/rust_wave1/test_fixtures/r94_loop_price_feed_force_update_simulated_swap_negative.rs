use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePriceAware;
#[contractimpl]
impl SafePriceAware {
    // OK: no force flag — only returns cached price, caller can't pick block
    pub fn get_current_price(in_amount: u128) -> u128 {
        let _ = in_amount;
        cached_price()
    }
}
fn cached_price() -> u128 { 0 }
