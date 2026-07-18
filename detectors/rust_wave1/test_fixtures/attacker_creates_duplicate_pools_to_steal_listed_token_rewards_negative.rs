use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub token0: [u8; 32],
    pub token1: [u8; 32],
    pub fee: u24,
    pub tick_spacing: i32,
    pub hooks: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct PoolId([u8; 32]);

pub struct RewardHook {
    pools: HashMap<PoolId, PoolState>,
    listed_tokens: HashMap<[u8; 32], TokenInfo>,
    // Canonical pool registry: token pair -> canonical pool id
    canonical_pools: HashMap<([u8; 32], [u8; 32]), PoolId>,
}

#[derive(Clone, Debug)]
pub struct PoolState {
    pub liquidity: u128,
    pub rewards_accrued: u128,
}

#[derive(Clone, Debug)]
pub struct TokenInfo {
    pub is_listed: bool,
    pub reward_rate: u64,
}

pub struct u24(pub u32);

impl RewardHook {
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
            listed_tokens: HashMap::new(),
            canonical_pools: HashMap::new(),
        }
    }

    pub fn register_pool(&mut self, pool_key: &PoolKey) -> Result<PoolId, &'static str> {
        let pool_id = self.derive_pool_id(pool_key);
        
        // Only allow one canonical pool per (token0, token1) pair
        let pair = if pool_key.token0 < pool_key.token1 {
            (pool_key.token0, pool_key.token1)
        } else {
            (pool_key.token1, pool_key.token0)
        };
        
        if self.canonical_pools.contains_key(&pair) {
            return Err("Pool already exists for this token pair");
        }
        
        self.canonical_pools.insert(pair, pool_id.clone());
        self.pools.insert(pool_id.clone(), PoolState {
            liquidity: 0,
            rewards_accrued: 0,
        });
        
        Ok(pool_id)
    }

    pub fn distribute_rewards(&mut self, pool_id: &PoolId, amount: u128) -> Result<(), &'static str> {
        let pool = self.pools.get_mut(pool_id)
            .ok_or("Pool not found")?;
        pool.rewards_accrued += amount;
        Ok(())
    }

    pub fn get_pool_rewards(&self, pool_id: &PoolId) -> Option<u128> {
        self.pools.get(pool_id).map(|p| p.rewards_accrued)
    }

    fn derive_pool_id(&self, pool_key: &PoolKey) -> PoolId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        pool_key.hash(&mut hasher);
        let hash = hasher.finish();
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&hash.to_le_bytes());
        PoolId(bytes)
    }
}

fn main() {
    let mut hook = RewardHook::new();
    let pool_key = PoolKey {
        token0: [1u8; 32],
        token1: [2u8; 32],
        fee: u24(3000),
        tick_spacing: 60,
        hooks: [0u8; 32],
    };
    let id = hook.register_pool(&pool_key).unwrap();
    hook.distribute_rewards(&id, 1000).unwrap();
    assert_eq!(hook.get_pool_rewards(&id), Some(1000));
    
    // Cannot register duplicate pool for same token pair
    let pool_key2 = PoolKey {
        token0: [1u8; 32],
        token1: [2u8; 32],
        fee: u24(500),
        tick_spacing: 10,
        hooks: [3u8; 32],
    };
    assert!(hook.register_pool(&pool_key2).is_err());
}