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
    pub liquidity: u128,
}

pub struct RewardHook {
    pools: HashMap<PoolId, PoolState>,
    pair_rewards: HashMap<([u8; 32], [u8; 32]), u128>,
}

impl RewardHook {
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
            pair_rewards: HashMap::new(),
        }
    }

    pub fn register_pool(&mut self, pool_key: &PoolKey) -> PoolId {
        let pool_id = self.derive_pool_id(pool_key);
        self.pools.insert(pool_id.clone(), PoolState { liquidity: 0 });
        pool_id
    }

    pub fn distribute_pair_rewards(&mut self, token0: [u8; 32], token1: [u8; 32], amount: u128) {
        let pair = if token0 < token1 {
            (token0, token1)
        } else {
            (token1, token0)
        };
        *self.pair_rewards.entry(pair).or_insert(0) += amount;
    }

    pub fn claim_rewards_for_pool(&mut self, pool_key: &PoolKey) -> u128 {
        let pair = if pool_key.token0 < pool_key.token1 {
            (pool_key.token0, pool_key.token1)
        } else {
            (pool_key.token1, pool_key.token0)
        };
        self.pair_rewards.get(&pair).copied().unwrap_or(0)
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
    hook.register_pool(&listed_pool);
    hook.distribute_pair_rewards([1u8; 32], [2u8; 32], 10_000);

    let duplicate_pool = PoolKey {
        token0: [1u8; 32],
        token1: [2u8; 32],
        fee: 500,
        tick_spacing: 10,
        hooks: [99u8; 32],
    };
    hook.register_pool(&duplicate_pool);

    let stolen = hook.claim_rewards_for_pool(&duplicate_pool);
    assert_eq!(stolen, 10_000);
}
