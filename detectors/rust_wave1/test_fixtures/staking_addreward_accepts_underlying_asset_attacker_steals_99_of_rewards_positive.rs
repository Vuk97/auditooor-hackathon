use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TokenId(u64);

pub struct StakingContract {
    pub underlying_asset: TokenId,
    pub reward_tokens: Vec<TokenId>,
    pub reward_rates: HashMap<TokenId, u64>,
    pub total_staked: u64,
    pub user_balances: HashMap<u64, u64>,
    // Tracks "reward pool" balance — but underlying staked amount is conflated
    pub reward_pool_balances: HashMap<TokenId, u64>,
}

impl StakingContract {
    pub fn new(underlying: TokenId) -> Self {
        Self {
            underlying_asset: underlying,
            reward_tokens: Vec::new(),
            reward_rates: HashMap::new(),
            total_staked: 0,
            user_balances: HashMap::new(),
            reward_pool_balances: HashMap::new(),
        }
    }

    // VULNERABLE: No check that token != underlying_asset
    pub fn add_reward_token(&mut self, token: TokenId, rate_per_block: u64) -> Result<(), &'static str> {
        if self.reward_tokens.contains(&token) {
            return Err("Reward token already exists");
        }
        self.reward_tokens.push(token);
        self.reward_rates.insert(token, rate_per_block);
        Ok(())
    }

    pub fn stake(&mut self, user: u64, amount: u64) {
        self.total_staked += amount;
        *self.user_balances.entry(user).or_insert(0) += amount;
    }

    // VULNERABLE: When underlying is also a "reward", total_staked is treated as reward pool
    pub fn add_rewards_to_pool(&mut self, token: TokenId, amount: u64) {
        *self.reward_pool_balances.entry(token).or_insert(0) += amount;
    }

    pub fn claim_rewards(&mut self, user: u64, reward_token: TokenId) -> u64 {
        let user_stake = self.user_balances.get(&user).copied().unwrap_or(0);
        let rate = self.reward_rates.get(&reward_token).copied().unwrap_or(0);
        
        // CRITICAL BUG: If reward_token == underlying_asset,
        // total_staked (all users' deposits) is treated as claimable "reward pool"
        let reward_pool = if reward_token == self.underlying_asset {
            self.total_staked // All staked underlying becomes "claimable"
        } else {
            self.reward_pool_balances.get(&reward_token).copied().unwrap_or(0)
        };
        
        // Attacker seeds huge rate, then claims disproportionate share
        let share = if self.total_staked > 0 {
            user_stake * reward_pool / self.total_staked
        } else {
            0
        };
        
        // Apply inflated rate multiplier (simplified: in real bug, per-block accrual)
        share * rate / 1000
    }
}

fn main() {
    let underlying = TokenId(1);
    let mut contract = StakingContract::new(underlying);
    
    // ATTACK: Add underlying asset as its own reward with huge rate
    contract.add_reward_token(underlying, 999_999).unwrap();
    
    // Victims stake
    contract.stake(100, 1000);
    contract.stake(101, 1000);
    
    // Attacker stakes minimal amount
    contract.stake(999, 1);
    
    // Attacker claims: total_staked (2001) is treated as "reward pool"
    // With rate 999_999, drains virtually all value
    let stolen = contract.claim_rewards(999, underlying);
    println!("Vulnerable: attacker can steal ~{} from reward pool", stolen);
}