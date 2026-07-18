use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub token0: [u8; 32],
    pub token1: [u8; 32],
    pub fee: u24,
    pub tick_spacing: i32,
    pub hooks: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoolId([u8; 32]);

pub struct RewardHook {
    pools: HashMap<PoolId, PoolState>,
    listed_tokens: HashMap<[u8; 32], TokenInfo>,
    // BUG: rewards keyed only by (token0, token1), not full PoolKey
    rewards_by_token_pair: HashMap<([u8; 32], [u8; 32]), u128>,
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
            rewards_by_token_pair: HashMap::new(),
        }
    }

    pub fn register_pool(&mut self, pool_key: &PoolKey) -> PoolId {
        let pool_id = self.derive_pool_id(pool_key);
        self.pools.insert(pool_id.clone(), PoolState {
            liquidity: 0,
            rewards_accrued: 0,
        });
        pool_id
    }

    // BUG: Distribute rewards to ALL pools sharing (token0, token1)
    // Attacker can create duplicate pool with different fee/tickSpacing/hooks
    // and steal rewards intended for legitimate pool
    pub fn distribute_rewards(&mut self, token0: [u8; 32], token1: [u8; 32], amount: u128) {
        let pair = if token0 < token1 {
            (token0, token1)
        } else {
            (token1, token0)
        };
        *self.rewards_by_token_pair.entry(pair).or_insert(0) += amount;
    }

    // BUG: Any pool with same (token0, token1) can claim rewards
    pub fn claim_rewards(&mut self, pool_key: &PoolKey) -> u128 {
        let pair = if pool_key.token0 < pool_key.token1 {
            (pool_key.token0, pool_key.token1)
        } else {
            (pool_key.token1, pool_key.token0)
        };
        self.rewards_by_token_pair.get(&pair).copied().unwrap_or(0)
    }

    pub fn add_listed_token(&mut self, token: [u8; 32], info: TokenInfo) {
        self.listed_tokens.insert(token, info);
    }

    pub fn is_listed(&self, token: &[u8; 32]) -> bool {
        self.listed_tokens.get(token).map(|i| i.is_listed).unwrap_or(false)
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
    
    // Legitimate pool for listed token pair
    let legit_pool = PoolKey {
        token0: [1u8; 32],
        token1: [2u8; 32],
        fee: u24(3000),
        tick_spacing: 60,
        hooks: [0u8; 32],
    };
    let legit_id = hook.register_pool(&legit_pool);
    hook.add_listed_token([1u8; 32], TokenInfo { is_listed: true, reward_rate: 100 });
    hook.add_listed_token([2u8; 32], TokenInfo { is_listed: true, reward_rate: 100 });
    
    // Rewards distributed for token pair
    hook.distribute_rewards([1u8; 32], [2u8; 32], 10000);
    
    // Attacker creates duplicate pool with different parameters
    let attacker_pool = PoolKey {
        token0: [1u8; 32],
        token1: [2u8; 32],
        fee: u24(500),        // Different fee
        tick_spacing: 10,      // Different tick spacing
        hooks: [99u8; 32],     // Different hooks
    };
    let attacker_id = hook.register_pool(&attacker_pool);
    
    // Attacker steals rewards intended for legitimate pool!
    let stolen = hook.claim_rewards(&attacker_pool);
    assert_eq!(stolen, 10000);
    
    // Legitimate pool also sees rewards (but attacker already drained them)
    let legit_rewards = hook.claim_rewards(&legit_pool);
    assert_eq!(legit_rewards, 10000); // Same rewards, double-counted accounting bug
}