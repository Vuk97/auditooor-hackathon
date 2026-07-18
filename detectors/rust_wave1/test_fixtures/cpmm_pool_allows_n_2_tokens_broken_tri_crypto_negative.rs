use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PoolType {
    ConstantProduct,
    StableSwap,
}

pub struct PoolConfig {
    pub pool_type: PoolType,
    pub asset_count: u8,
    pub assets: Vec<u64>,
}

pub struct PoolManager;

impl PoolManager {
    pub fn create_pool(pool_type: PoolType, asset_count: u8, assets: Vec<u64>) -> Result<PoolConfig, &'static str> {
        // CPMM only supports exactly 2 tokens
        if pool_type == PoolType::ConstantProduct && asset_count != 2 {
            return Err("ConstantProduct pools require exactly 2 assets");
        }
        
        if asset_count < 2 || asset_count > 8 {
            return Err("Asset count must be between 2 and 8");
        }
        
        if assets.len() as u8 != asset_count {
            return Err("Asset count mismatch");
        }
        
        Ok(PoolConfig {
            pool_type,
            asset_count,
            assets,
        })
    }
    
    pub fn get_invariant(pool: &PoolConfig) -> Result<u128, &'static str> {
        match pool.pool_type {
            PoolType::ConstantProduct => {
                // x * y = k, only valid for 2 assets
                if pool.asset_count != 2 || pool.assets.len() != 2 {
                    return Err("Invalid CPMM configuration");
                }
                Ok(pool.assets[0] as u128 * pool.assets[1] as u128)
            }
            PoolType::StableSwap => {
                // Stable swap supports n >= 2
                let sum: u128 = pool.assets.iter().map(|&a| a as u128).sum();
                Ok(sum)
            }
        }
    }
}

fn main() {
    // Valid: CPMM with 2 assets
    let pool = PoolManager::create_pool(PoolType::ConstantProduct, 2, vec![1000, 2000]).unwrap();
    println!("CPMM invariant: {:?}", PoolManager::get_invariant(&pool));
    
    // Valid: StableSwap with 3 assets
    let stable_pool = PoolManager::create_pool(PoolType::StableSwap, 3, vec![1000, 2000, 3000]).unwrap();
    println!("StableSwap invariant: {:?}", PoolManager::get_invariant(&stable_pool));
    
    // Rejected: CPMM with 3 assets
    let invalid = PoolManager::create_pool(PoolType::ConstantProduct, 3, vec![1000, 2000, 3000]);
    assert!(invalid.is_err());
}