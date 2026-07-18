use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePerp;
#[contractimpl]
impl SafePerp {
    // OK: uses mul_div_up for weighted-average open_price
    pub fn fill(old_size: u128, old_price: u128, fill_size: u128, fill_price: u128) -> u128 {
        let total_size = old_size + fill_size;
        let open_price = mul_div_up(old_size * old_price + fill_size * fill_price, 1, total_size);
        open_price
    }
}
fn mul_div_up(_n: u128, _d: u128, _t: u128) -> u128 { 0 }
