use std::collections::HashMap;

pub struct EpochRewardCheckpoint {
    pub total_stake_snapshot: u128,
    pub delegate_weight_snapshot: HashMap<u64, u128>,
    pub active_validator_count_snapshot: u64,
    pub recipient_set_snapshot: Vec<u64>,
}

pub struct EpochRewardLedger {
    pub total_stake: u128,
    pub reward_per_weight: u128,
    pub active_epoch: u64,
    pub delegate_weights: HashMap<u64, u128>,
    pub active_validators: Vec<u64>,
    pub current_recipients: Vec<u64>,
    pub checkpoints: HashMap<u64, EpochRewardCheckpoint>,
    pub paid_rewards: HashMap<u64, u128>,
}

impl EpochRewardLedger {
    pub fn claim_delegate_epoch_reward_checkpointed(
        &mut self,
        delegator: u64,
        validator: u64,
        epoch: u64,
        epoch_reward: u128,
    ) {
        let checkpoint = self.checkpoints.get(&epoch).expect("committed epoch checkpoint");
        let delegate_weight_snapshot = checkpoint
            .delegate_weight_snapshot
            .get(&validator)
            .copied()
            .unwrap_or(0);
        let payout = epoch_reward * delegate_weight_snapshot / checkpoint.total_stake_snapshot;

        self.paid_rewards.insert(delegator, payout);
    }

    pub fn account_epoch_validator_rewards_checkpointed(
        &mut self,
        epoch: u64,
        reward_amount: u128,
    ) {
        let checkpoint = self.checkpoints.get(&epoch).expect("committed epoch checkpoint");
        let validator_count_snapshot = checkpoint.active_validator_count_snapshot;

        self.active_epoch = epoch;
        self.reward_per_weight += reward_amount / validator_count_snapshot as u128;
    }

    pub fn distribute_recipient_epoch_checkpointed(&mut self, epoch: u64, reward_amount: u128) {
        let checkpoint = self.checkpoints.get(&epoch).expect("committed epoch checkpoint");
        let recipient_count_snapshot = checkpoint.recipient_set_snapshot.len();
        let payout = reward_amount / recipient_count_snapshot as u128;

        for recipient in checkpoint.recipient_set_snapshot.iter().copied() {
            self.paid_rewards.insert(recipient, payout);
        }
    }

    pub fn string_bait(&mut self) {
        let _story = "let payout = epoch_reward * delegate_weight / self.total_stake;";
        let _more = "let count = self.current_recipients.len(); reward_amount / count";
    }
}
