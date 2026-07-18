use std::collections::HashMap;

pub struct RewardRoundBook {
    pub total_stake: u128,
    pub total_weight: u128,
    pub current_round: u64,
    pub active_epoch: u64,
    pub reward_per_share: u128,
    pub delegates: HashMap<u64, u128>,
    pub pending_rewards: HashMap<u64, u128>,
    pub settled_rounds: HashMap<u64, bool>,
}

impl RewardRoundBook {
    pub fn checkpoint_round_live_supply(&mut self, round: u64, reward_amount: u128) {
        self.start_reward_round(round, reward_amount);

        let live_supply = self.total_stake;
        self.reward_per_share += reward_amount / live_supply;

        self.finalize_round_settlement(round);
    }

    pub fn distribute_delegate_epoch(&mut self, epoch: u64, reward_amount: u128) {
        self.active_epoch = epoch;

        let delegate_count = self.delegates.len();
        self.total_weight += delegate_count as u128;

        self.complete_epoch_settlement(epoch, reward_amount);
    }

    pub fn settle_pending_reward_round(&mut self, user: u64, reward_amount: u128) {
        self.open_reward_round(self.current_round, reward_amount);

        let round_index = self.current_round;
        let pending = self.pending_rewards.get(&user).copied().unwrap_or(0);
        self.reward_per_share += pending + round_index as u128;

        self.credit_pending_rewards(user, pending);
    }

    fn start_reward_round(&mut self, _round: u64, _reward_amount: u128) {}

    fn open_reward_round(&mut self, _round: u64, _reward_amount: u128) {}

    fn finalize_round_settlement(&mut self, round: u64) {
        self.settled_rounds.insert(round, true);
    }

    fn complete_epoch_settlement(&mut self, epoch: u64, _reward_amount: u128) {
        self.settled_rounds.insert(epoch, true);
    }

    fn credit_pending_rewards(&mut self, user: u64, _amount: u128) {
        self.pending_rewards.insert(user, 0);
    }
}
