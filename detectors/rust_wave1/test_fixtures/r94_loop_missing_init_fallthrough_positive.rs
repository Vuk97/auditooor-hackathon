use soroban_sdk::{contract, contractimpl};
pub struct MantraResolver;
impl MantraResolver {
    pub fn convert_to_denom(&self, _x: u64) -> u64 { 0 }
}
#[contract]
pub struct FeemarketKeeper;
#[contractimpl]
impl FeemarketKeeper {
    // BUG: init exists; references to MantraResolver are elsewhere (used downstream)
    // but init never wires the custom resolver — framework default is used.
    pub fn new_feemarket_keeper(chain_id: u64) -> u64 {
        chain_id
    }
    pub fn use_resolver_somewhere(x: u64) -> u64 {
        let r = MantraResolver;
        r.convert_to_denom(x)
    }
}
