use std::collections::HashMap;

pub struct EpochRewardLedger {
    pub total_stake: u128,
    pub reward_per_weight: u128,
    pub active_epoch: u64,
    pub delegate_weights: HashMap<u64, u128>,
    pub active_validators: Vec<u64>,
    pub current_recipients: Vec<u64>,
    pub paid_rewards: HashMap<u64, u128>,
}

impl EpochRewardLedger {
    pub fn claim_delegate_epoch_reward(
        &mut self,
        delegator: u64,
        validator: u64,
        epoch_reward: u128,
    ) {
        let delegate_weight = self.delegate_weights.get(&validator).copied().unwrap_or(0);
        let payout = epoch_reward * delegate_weight / self.total_stake;

        self.paid_rewards.insert(delegator, payout);
    }

    pub fn account_epoch_validator_rewards(&mut self, epoch: u64, reward_amount: u128) {
        self.active_epoch = epoch;

        let active_validator_count = self.active_validators.len();
        self.reward_per_weight += reward_amount / active_validator_count as u128;
    }

    pub fn distribute_current_recipient_epoch(&mut self, reward_amount: u128) {
        let recipient_count = self.current_recipients.len();
        let payout = reward_amount / recipient_count as u128;

        for recipient in self.current_recipients.iter().copied() {
            self.paid_rewards.insert(recipient, payout);
        }
    }
}
