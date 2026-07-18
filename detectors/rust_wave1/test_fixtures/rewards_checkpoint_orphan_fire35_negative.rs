use std::collections::HashMap;

pub struct RewardBook {
    pub position_owner: HashMap<u64, u64>,
    pub owner_shares: HashMap<u64, u128>,
    pub delegations: HashMap<u64, u64>,
    pub validator_stake: HashMap<u64, u128>,
    pub stakes: HashMap<u64, u128>,
    pub total_stake: u128,
    pub reward_per_share: u128,
    pub user_reward_index: HashMap<u64, u128>,
}

impl RewardBook {
    pub fn transfer_position(&mut self, position_id: u64, from: u64, to: u64, shares: u128) {
        self.checkpoint_account(from);
        self.checkpoint_account(to);

        self.position_owner.insert(position_id, to);
        let from_shares = self.owner_shares.get(&from).copied().unwrap_or(0);
        self.owner_shares.insert(from, from_shares - shares);
        let to_shares = self.owner_shares.get(&to).copied().unwrap_or(0);
        self.owner_shares.insert(to, to_shares + shares);
    }

    pub fn redelegate(&mut self, delegator: u64, old_validator: u64, new_validator: u64, stake: u128) {
        self.checkpoint_delegation_rewards(delegator, old_validator);

        self.delegations.insert(delegator, new_validator);
        let old_weight = self.validator_stake.get(&old_validator).copied().unwrap_or(0);
        self.validator_stake.insert(old_validator, old_weight - stake);
        let new_weight = self.validator_stake.get(&new_validator).copied().unwrap_or(0);
        self.validator_stake.insert(new_validator, new_weight + stake);
    }

    pub fn withdraw_stake(&mut self, account: u64, amount: u128) {
        self.settle_account_rewards(account);

        let previous = self.stakes.get(&account).copied().unwrap_or(0);
        self.stakes.insert(account, previous - amount);
        self.total_stake -= amount;
    }

    pub fn string_bait(&mut self) {
        let _story = "delegations.insert(delegator, new_validator); checkpoint_account(account);";
        let _reward_story = "position_owner.insert(position_id, to); settle_account_rewards(account);";
    }

    fn checkpoint_account(&mut self, _user: u64) {}

    fn checkpoint_delegation_rewards(&mut self, _delegator: u64, _validator: u64) {}

    fn settle_account_rewards(&mut self, _account: u64) {}
}
