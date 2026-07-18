use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: uses TWAP
    pub fn burn(shares: u128, twap_price: u128) -> u128 {
        let impermanent_loss = compute_il_twap(twap_price);
        shares + impermanent_loss
    }
}
fn compute_il_twap(_p: u128) -> u128 { 0 }
