use std::collections::HashMap;

pub struct RewardSharePool {
    balances: HashMap<u64, u128>,
    user_reward_per_token_paid: HashMap<u64, u128>,
    accrued_rewards: HashMap<u64, u128>,
    reward_per_token_stored: u128,
}

impl RewardSharePool {
    pub fn transfer_shares(&mut self, from: u64, to: u64, amount: u128) {
        self.settle_rewards(from);
        self.settle_rewards(to);

        let from_balance = *self.balances.get(&from).unwrap_or(&0);
        let to_balance = *self.balances.get(&to).unwrap_or(&0);
        self.balances.insert(from, from_balance - amount);
        self.balances.insert(to, to_balance + amount);
    }

    fn settle_rewards(&mut self, user: u64) {
        self.user_reward_per_token_paid
            .insert(user, self.reward_per_token_stored);
        self.accrued_rewards.insert(user, 0);
    }
}
