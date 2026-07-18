use soroban_sdk::{contract, contractimpl};
pub struct MantraResolver;
impl MantraResolver {
    pub fn convert_to_denom(&self, _x: u64) -> u64 { 0 }
}
#[contract]
pub struct FeemarketKeeper;
#[contractimpl]
impl FeemarketKeeper {
    // OK: init wires MantraResolver explicitly
    pub fn new_feemarket_keeper(chain_id: u64) -> (u64, MantraResolver) {
        (chain_id, MantraResolver)
    }
}
