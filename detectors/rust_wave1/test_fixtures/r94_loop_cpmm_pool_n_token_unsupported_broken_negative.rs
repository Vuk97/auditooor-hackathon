use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeFactory;
#[contractimpl]
impl SafeFactory {
    // OK: require assets.len() == 2 for ConstantProduct
    pub fn create_pool(pool_type: PoolType, assets: &[u64]) {
        match pool_type {
            PoolType::ConstantProduct => {
                if assets.len() == 2 { register(assets); }
            }
            _ => {}
        }
    }
}
pub enum PoolType { ConstantProduct, StableSwap }
fn register(_a: &[u64]) {}
