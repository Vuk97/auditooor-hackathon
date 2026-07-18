use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Perp;
#[contractimpl]
impl Perp {
    // BUG: open_price uses rounding-down integer division
    pub fn fill(old_size: u128, old_price: u128, fill_size: u128, fill_price: u128) -> u128 {
        let total_size = old_size + fill_size;
        let open_price = (old_size * old_price + fill_size * fill_price) / total_size;
        open_price
    }
}
