use std::collections::HashMap;

// Safe version: prevents recursive reward stacking by tracking
// the underlying token source and blocking re-deposit of yield-bearing tokens

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TokenId(u64);

#[derive(Clone)]
struct UserPosition {
    balance: u64,
    underlying_source: Option<TokenId>, // Tracks if this is a derived yield-bearing position
}

struct RewardPool {
    total_supply: u64,
    reward_per_token_stored: u64,
    user_positions: HashMap<u64, UserPosition>, // user_id -> position
    // Registry of tokens that are yield-bearing (cannot be used as collateral)
    yield_bearing_tokens: HashMap<TokenId, bool>,
}

struct LendingMarket {
    pools: HashMap<TokenId, RewardPool>,
    // Tracks deposited collateral per user per market
    collateral_deposits: HashMap<(u64, TokenId), u64>,
}

impl LendingMarket {
    fn new() -> Self {
        Self {
            pools: HashMap::new(),
            collateral_deposits: HashMap::new(),
        }
    }

    fn register_yield_bearing(&mut self, token: TokenId) {
        self.pools.entry(token.clone()).or_insert_with(|| RewardPool {
            total_supply: 0,
            reward_per_token_stored: 0,
            user_positions: HashMap::new(),
            yield_bearing_tokens: HashMap::new(),
        });
        for pool in self.pools.values_mut() {
            pool.yield_bearing_tokens.insert(token.clone(), true);
        }
    }

    // SAFE: Check if token is yield-bearing before allowing as collateral
    fn deposit_collateral(
        &mut self,
        user: u64,
        token: TokenId,
        amount: u64,
        source_position: Option<TokenId>, // None = fresh tokens, Some = from another pool
    ) -> Result<(), &'static str> {
        // CRITICAL FIX: Block recursive deposits of yield-bearing tokens
        if let Some(source) = &source_position {
            if self.is_yield_bearing(source) {
                return Err("Cannot use yield-bearing token as collateral");
            }
        }
        
        // Also block if the deposited token itself is yield-bearing and has a source
        if self.is_yield_bearing(&token) && source_position.is_some() {
            return Err("Cannot recursively deposit yield-bearing tokens");
        }

        let pool = self.pools.entry(token.clone()).or_insert_with(|| RewardPool {
            total_supply: 0,
            reward_per_token_stored: 0,
            user_positions: HashMap::new(),
            yield_bearing_tokens: HashMap::new(),
        });

        let position = pool.user_positions.entry(user).or_insert_with(|| UserPosition {
            balance: 0,
            underlying_source: source_position.clone(),
        });

        position.balance += amount;
        pool.total_supply += amount;
        
        self.collateral_deposits.insert((user, token), amount);
        Ok(())
    }

    fn is_yield_bearing(&self, token: &TokenId) -> bool {
        self.pools.values().any(|p| p.yield_bearing_tokens.get(token).copied().unwrap_or(false))
    }

    fn claim_rewards(&self, user: u64, token: &TokenId) -> u64 {
        let pool = match self.pools.get(token) {
            Some(p) => p,
            None => return 0,
        };
        let position = match pool.user_positions.get(&user) {
            Some(p) => p,
            None => return 0,
        };
        // Simple reward calculation based on proportional share
        if pool.total_supply == 0 {
            return 0;
        }
        position.balance * pool.reward_per_token_stored / pool.total_supply
    }
}

fn main() {
    let mut market = LendingMarket::new();
    let underlying = TokenId(1);
    let yield_token = TokenId(2);
    
    market.register_yield_bearing(yield_token.clone());
    
    // Normal deposit of underlying as collateral - succeeds
    market.deposit_collateral(1, underlying.clone(), 1000, None).unwrap();
    
    // Attempt to deposit yield-bearing token as collateral for another position - BLOCKED
    let result = market.deposit_collateral(1, underlying.clone(), 500, Some(yield_token.clone()));
    assert!(result.is_err(), "Should block recursive yield-bearing collateral");
    
    println!("Clean fixture: recursive deposit blocked");
}