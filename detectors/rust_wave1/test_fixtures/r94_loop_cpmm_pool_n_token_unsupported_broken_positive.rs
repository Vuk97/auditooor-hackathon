use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Factory;
#[contractimpl]
impl Factory {
    // BUG: creates ConstantProduct pool without requiring exactly 2 tokens
    pub fn create_pool(pool_type: PoolType, assets: &[u64]) {
        match pool_type {
            PoolType::ConstantProduct => {
                register(assets);
            }
            _ => {}
        }
    }
}
pub enum PoolType { ConstantProduct, StableSwap }
fn register(_a: &[u64]) {}
