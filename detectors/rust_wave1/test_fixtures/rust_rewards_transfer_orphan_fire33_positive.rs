use std::collections::HashMap;

pub struct HolderRewardState {
    shares: u128,
    reward_debt: u128,
    accrued_rewards: u128,
}

pub struct BoostDelegation {
    boost_weight: u128,
    paid_index: u128,
}

pub struct RewardVault {
    holders: HashMap<u64, HolderRewardState>,
    delegation_boosts: HashMap<(u64, u64), BoostDelegation>,
    acc_reward_per_share: u128,
    reward_index: u128,
}

impl RewardVault {
    pub fn transfer_vault_shares(&mut self, from: u64, to: u64, amount: u128) {
        let from_shares = self.holders.get(&from).map(|h| h.shares).unwrap_or(0);
        let to_shares = self.holders.get(&to).map(|h| h.shares).unwrap_or(0);

        self.holders.insert(
            from,
            HolderRewardState {
                shares: from_shares - amount,
                reward_debt: self.acc_reward_per_share,
                accrued_rewards: 0,
            },
        );
        self.holders.insert(
            to,
            HolderRewardState {
                shares: to_shares + amount,
                reward_debt: 0,
                accrued_rewards: 0,
            },
        );

        self.checkpoint_rewards(from);
        self.checkpoint_rewards(to);
    }

    pub fn move_delegation_boost(
        &mut self,
        delegator: u64,
        old_delegate: u64,
        new_delegate: u64,
        boost: u128,
    ) {
        self.delegation_boosts.insert(
            (delegator, old_delegate),
            BoostDelegation {
                boost_weight: 0,
                paid_index: self.reward_index,
            },
        );
        self.delegation_boosts.insert(
            (delegator, new_delegate),
            BoostDelegation {
                boost_weight: boost,
                paid_index: 0,
            },
        );

        self.checkpoint_delegation_rewards(delegator, old_delegate);
        self.checkpoint_delegation_rewards(delegator, new_delegate);
    }

    fn checkpoint_rewards(&mut self, user: u64) {
        if let Some(holder) = self.holders.get_mut(&user) {
            holder.accrued_rewards += holder.shares * self.acc_reward_per_share;
            holder.reward_debt = self.acc_reward_per_share;
        }
    }

    fn checkpoint_delegation_rewards(&mut self, delegator: u64, delegate: u64) {
        if let Some(boost) = self.delegation_boosts.get_mut(&(delegator, delegate)) {
            boost.paid_index = self.reward_index;
        }
    }
}
