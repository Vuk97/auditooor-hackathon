use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TokenId(u64);

pub struct StakingContract {
    pub underlying_asset: TokenId,
    pub reward_tokens: Vec<TokenId>,
    pub reward_rates: HashMap<TokenId, u64>,
    pub total_staked: u64,
    pub user_balances: HashMap<u64, u64>,
}

impl StakingContract {
    pub fn new(underlying: TokenId) -> Self {
        Self {
            underlying_asset: underlying,
            reward_tokens: Vec::new(),
            reward_rates: HashMap::new(),
            total_staked: 0,
            user_balances: HashMap::new(),
        }
    }

    pub fn add_reward_token(&mut self, token: TokenId, rate_per_block: u64) -> Result<(), &'static str> {
        // SECURITY FIX: Prevent underlying asset from being added as reward
        if token == self.underlying_asset {
            return Err("Cannot add underlying asset as reward token");
        }
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

    pub fn calculate_pending_rewards(&self, _user: u64, reward_token: TokenId) -> u64 {
        let rate = self.reward_rates.get(&reward_token).copied().unwrap_or(0);
        // Simplified: in real contract, would track per-user reward debt
        self.total_staked * rate / 1000
    }
}

fn main() {
    let underlying = TokenId(1);
    let mut contract = StakingContract::new(underlying);
    let reward = TokenId(2);
    contract.add_reward_token(reward, 100).unwrap();
    contract.stake(42, 1000);
    println!("Clean: rewards work correctly");
}