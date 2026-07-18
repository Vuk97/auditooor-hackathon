use std::collections::HashMap;

pub struct RewardAccount {
    pub balance: u128,
    pub accrued_rewards: u128,
    pub reward_debt: u128,
}

pub struct RewardsVault {
    pub accounts: HashMap<u64, RewardAccount>,
    pub balances: HashMap<u64, u128>,
    pub vault_allocations: HashMap<u64, u128>,
    pub total_reward_denominator: u128,
    pub delegated_weight: HashMap<u64, u128>,
    pub vote_checkpoints: HashMap<u64, Vec<(u64, u128)>>,
    pub reward_checkpoint_epoch: u64,
}

impl RewardsVault {
    pub fn transfer_after_accrued_rewards_settled(&mut self, from: u64, to: u64, amount: u128) {
        self.settle_accrued_rewards(from);
        self.settle_accrued_rewards(to);

        let from_balance = self.balances.get(&from).copied().unwrap_or(0);
        self.balances.insert(from, from_balance - amount);
        let to_balance = self.balances.get(&to).copied().unwrap_or(0);
        self.balances.insert(to, to_balance + amount);
    }

    pub fn allocate_vault_after_reward_checkpoint(&mut self, vault_id: u64, allocation: u128) {
        self.sync_reward_checkpoint(vault_id);

        self.vault_allocations.insert(vault_id, allocation);
        self.total_reward_denominator += allocation;
    }

    pub fn write_vote_checkpoint_after_reward_sync(
        &mut self,
        delegatee: u64,
        weight: u128,
        epoch: u64,
    ) {
        self.sync_vote_reward_checkpoint(delegatee);

        self.delegated_weight.insert(delegatee, weight);
        self.vote_checkpoints
            .entry(delegatee)
            .or_default()
            .push((epoch, weight));
    }

    pub fn string_bait(&mut self) {
        let _story = "self.balances.insert(from, from_balance - amount);";
        let _more = "self.vault_allocations.insert(vault_id, allocation);";
        let _vote = "self.delegated_weight.insert(delegatee, weight);";
    }

    fn settle_accrued_rewards(&mut self, user: u64) {
        if let Some(account) = self.accounts.get_mut(&user) {
            account.reward_debt += account.accrued_rewards;
            account.accrued_rewards = 0;
        }
    }

    fn sync_reward_checkpoint(&mut self, _vault_id: u64) {
        self.reward_checkpoint_epoch += 1;
    }

    fn sync_vote_reward_checkpoint(&mut self, _delegatee: u64) {
        self.reward_checkpoint_epoch += 1;
    }
}
