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
        // BUG: No validation that ConstantProduct requires exactly 2 tokens
        // CPMM invariant x*y=k breaks for n>2 tokens
        
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
                // BUG: Assumes 2 assets but never validated at creation
                // For n>2, this either panics or computes wrong invariant
                if pool.assets.len() < 2 {
                    return Err("Need at least 2 assets");
                }
                // Only multiplies first two, ignores rest for n>2
                Ok(pool.assets[0] as u128 * pool.assets[1] as u128)
            }
            PoolType::StableSwap => {
                let sum: u128 = pool.assets.iter().map(|&a| a as u128).sum();
                Ok(sum)
            }
        }
    }
    
    pub fn swap(pool: &PoolConfig, asset_in: usize, asset_out: usize, amount_in: u64) -> Result<u64, &'static str> {
        match pool.pool_type {
            PoolType::ConstantProduct => {
                // BUG: CPMM swap math undefined for n>2
                let k = Self::get_invariant(pool)?;
                let new_in = pool.assets[asset_in] as u128 + amount_in as u128;
                // This formula is only valid for 2-token pools
                let new_out = k / new_in;
                Ok((pool.assets[asset_out] as u128 - new_out) as u64)
            }
            PoolType::StableSwap => {
                // Simplified stable swap logic
                Ok(amount_in)
            }
        }
    }
}

fn main() {
    // BUG: Creates broken tri-crypto CPMM pool (3 assets)
    let broken_pool = PoolManager::create_pool(PoolType::ConstantProduct, 3, vec![1000, 2000, 3000]).unwrap();
    println!("Broken pool created: {:?}", broken_pool);
    
    // Wrong invariant computed (ignores 3rd asset)
    let inv = PoolManager::get_invariant(&broken_pool).unwrap();
    println!("Wrong invariant (should include 3rd asset): {}", inv);
    
    // Swap math is broken for n>2
    let out = PoolManager::swap(&broken_pool, 0, 1, 100).unwrap();
    println!("Potentially wrong swap output: {}", out);
}