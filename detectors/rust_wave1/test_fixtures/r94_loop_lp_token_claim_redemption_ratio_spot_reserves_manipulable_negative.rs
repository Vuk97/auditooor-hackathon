use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn current_reserve(_idx: usize) -> u128 { 1_000_000 }
fn snapshot_reserve(_idx: usize) -> u128 { 800_000 }
fn total_supply() -> u128 { 100_000 }
#[contract]
pub struct AssetHandler;
#[contractimpl]
impl AssetHandler {
    // SAFE: uses snapshot_reserve (stored at deposit time) not current
    pub fn get_cash_claims(lp_amount: u128) -> u128 {
        let _ignored = current_reserve(0);
        let reserve = snapshot_reserve(0);
        lp_amount * reserve / total_supply()
    }
}
