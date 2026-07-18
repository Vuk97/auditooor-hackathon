use std::collections::HashMap;

// VULNERABLE version: allows recursive reward stacking by failing to
// track or validate the underlying source of deposited tokens

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TokenId(u64);

#[derive(Clone)]
struct UserPosition {
    balance: u64,
    // MISSING: no tracking of underlying_source
}

struct RewardPool {
    total_supply: u64,
    reward_per_token_stored: u64,
    user_positions: HashMap<u64, UserPosition>,
    // MISSING: no yield_bearing_tokens registry
}

struct LendingMarket {
    pools: HashMap<TokenId, RewardPool>,
    collateral_deposits: HashMap<(u64, TokenId), u64>,
}

impl LendingMarket {
    fn new() -> Self {
        Self {
            pools: HashMap::new(),
            collateral_deposits: HashMap::new(),
        }
    }

    fn register_incentivized_pool(&mut self, token: TokenId) {
        self.pools.insert(token, RewardPool {
            total_supply: 0,
            reward_per_token_stored: 1000, // Some reward rate
            user_positions: HashMap::new(),
        });
    }

    // VULNERABLE: No validation of token source, allows recursive deposits
    fn deposit_collateral(
        &mut self,
        user: u64,
        token: TokenId,
        amount: u64,
        // MISSING: no source_position parameter to track origin
    ) -> Result<(), &'static str> {
        let pool = self.pools.entry(token.clone()).or_insert_with(|| RewardPool {
            total_supply: 0,
            reward_per_token_stored: 0,
            user_positions: HashMap::new(),
        });

        let position = pool.user_positions.entry(user).or_insert_with(|| UserPosition {
            balance: 0,
            // MISSING: no underlying_source tracking
        });

        position.balance += amount;
        pool.total_supply += amount;
        
        self.collateral_deposits.insert((user, token), amount);
        Ok(())
    }

    // VULNERABLE: Claims rewards without checking for recursive stacking
    fn claim_rewards(&mut self, user: u64, token: &TokenId) -> u64 {
        let pool = match self.pools.get(token) {
            Some(p) => p,
            None => return 0,
        };
        let position = match pool.user_positions.get(&user) {
            Some(p) => p,
            None => return 0,
        };
        // Rewards calculated purely on balance, no check for recursive exposure
        if pool.total_supply == 0 {
            return 0;
        }
        // VULNERABILITY: Same underlying counted multiple times across recursive positions
        position.balance * pool.reward_per_token_stored
    }

    // VULNERABLE: Allows borrowing against collateral without source validation
    fn borrow_against_collateral(&self, user: u64, collateral_token: &TokenId) -> u64 {
        let deposit = self.collateral_deposits.get(&(user, collateral_token.clone())).copied().unwrap_or(0);
        // No check if collateral itself is borrowed/incentivized position
        deposit * 8 / 10 // 80% LTV
    }
}

fn main() {
    let mut market = LendingMarket::new();
    let underlying = TokenId(1);
    let incentivized_pool = TokenId(2);
    let lending_market = TokenId(3);
    
    market.register_incentivized_pool(incentivized_pool.clone());
    market.register_incentivized_pool(lending_market.clone());
    
    // Step 1: Deposit underlying into incentivized pool
    market.deposit_collateral(1, incentivized_pool.clone(), 1000).unwrap();
    
    // Step 2: VULNERABLE: Use the yield-bearing position as collateral for another pool
    // No validation prevents this recursive stacking
    market.deposit_collateral(1, lending_market.clone(), 1000).unwrap();
    // In real exploit, attacker would have minted yield tokens from step 1 and deposited those
    
    // Step 3: Claim rewards from both positions - same underlying counted twice
    let rewards_1 = market.claim_rewards(1, &incentivized_pool);
    let rewards_2 = market.claim_rewards(1, &lending_market);
    
    // Total rewards exceed fair share because position was double-counted
    println!("Vulnerable fixture: rewards_1={}, rewards_2={}, total={}", rewards_1, rewards_2, rewards_1 + rewards_2);
    
    // Attacker can repeat: borrow against lending position, re-deposit, stack further
    let borrow_capacity = market.borrow_against_collateral(1, &lending_market);
    println!("Can borrow {} against recursively stacked collateral", borrow_capacity);
}