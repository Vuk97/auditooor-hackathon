use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub token0: [u8; 32],
    pub token1: [u8; 32],
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoolId([u8; 32]);

pub struct PoolState {
    pub rewards_accrued: u128,
}

pub struct RewardHook {
    pools: HashMap<PoolId, PoolState>,
    canonical_pools: HashMap<([u8; 32], [u8; 32]), PoolId>,
    rewards_by_pool: HashMap<PoolId, u128>,
}

impl RewardHook {
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
            canonical_pools: HashMap::new(),
            rewards_by_pool: HashMap::new(),
        }
    }

    pub fn register_pool(&mut self, pool_key: &PoolKey) -> Result<PoolId, &'static str> {
        let pool_id = self.derive_pool_id(pool_key);
        let pair = if pool_key.token0 < pool_key.token1 {
            (pool_key.token0, pool_key.token1)
        } else {
            (pool_key.token1, pool_key.token0)
        };

        if self.canonical_pools.contains_key(&pair) {
            return Err("Pool already exists");
        }

        self.canonical_pools.insert(pair, pool_id.clone());
        self.pools.insert(pool_id.clone(), PoolState { rewards_accrued: 0 });
        Ok(pool_id)
    }

    pub fn distribute_rewards(&mut self, pool_id: &PoolId, amount: u128) -> Result<(), &'static str> {
        let pool = self.pools.get_mut(pool_id).ok_or("Pool not found")?;
        pool.rewards_accrued += amount;
        self.rewards_by_pool.insert(pool_id.clone(), pool.rewards_accrued);
        Ok(())
    }

    pub fn claim_rewards_for_pool(&self, pool_key: &PoolKey) -> Option<u128> {
        let pair = if pool_key.token0 < pool_key.token1 {
            (pool_key.token0, pool_key.token1)
        } else {
            (pool_key.token1, pool_key.token0)
        };
        let canonical = self.canonical_pools.get(&pair)?;
        let supplied = self.derive_pool_id(pool_key);
        if &supplied != canonical {
            return None;
        }
        self.rewards_by_pool.get(canonical).copied()
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
    let listed_pool = PoolKey {
        token0: [1u8; 32],
        token1: [2u8; 32],
        fee: 3000,
        tick_spacing: 60,
        hooks: [0u8; 32],
    };
    let pool_id = hook.register_pool(&listed_pool).unwrap();
    hook.distribute_rewards(&pool_id, 1000).unwrap();
    assert_eq!(hook.claim_rewards_for_pool(&listed_pool), Some(1000));

    let duplicate_pool = PoolKey {
        token0: [1u8; 32],
        token1: [2u8; 32],
        fee: 500,
        tick_spacing: 10,
        hooks: [99u8; 32],
    };
    assert!(hook.register_pool(&duplicate_pool).is_err());
    assert_eq!(hook.claim_rewards_for_pool(&duplicate_pool), None);
}
