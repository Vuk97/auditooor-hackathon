use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct RewardPool;

#[contractimpl]
impl RewardPool {
    pub fn delegate(&mut self, user: u64, new_validator: u64, stake: u128) {
        let previous = self.delegations.get(&user).unwrap_or(0);
        let _pending = self.reward_per_weight - self.user_reward_index.get(&user).unwrap_or(0);

        self.delegations.insert(&user, new_validator);
        self.validator_weight.insert(&new_validator, self.validator_weight.get(&new_validator).unwrap_or(0) + stake);
        self.total_weight += stake;

        self.sync_reward_accumulator(user);
        let _ = previous;
    }
}
