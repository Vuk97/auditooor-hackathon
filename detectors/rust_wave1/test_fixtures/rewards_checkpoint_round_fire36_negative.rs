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
    pub fn checkpoint_round_with_snapshot(&mut self, round: u64, reward_amount: u128) {
        let supply_snapshot = self.total_stake;

        self.start_reward_round(round, reward_amount);
        self.reward_per_share += reward_amount / supply_snapshot;
        self.finalize_round_settlement(round);
    }

    pub fn distribute_delegate_epoch_with_snapshot(&mut self, epoch: u64, reward_amount: u128) {
        let delegate_count_snapshot = self.delegates.len();

        self.active_epoch = epoch;
        self.total_weight += delegate_count_snapshot as u128;
        self.complete_epoch_settlement(epoch, reward_amount);
    }

    pub fn settle_then_read_for_report(&mut self, user: u64, reward_amount: u128) {
        let round_snapshot = self.current_round;
        let pending_snapshot = self.pending_rewards.get(&user).copied().unwrap_or(0);

        self.open_reward_round(round_snapshot, reward_amount);
        self.credit_pending_rewards(user, pending_snapshot);

        let _report_only = self.current_round;
        let _pending_after_settle = self.pending_rewards.get(&user).copied().unwrap_or(0);
    }

    pub fn string_bait(&mut self) {
        let _story = "start_reward_round(round, reward); let live_supply = self.total_stake; finalize_round_settlement(round);";
        let _pending = "open_reward_round(round, reward); pending_rewards.get(&user); credit_pending_rewards(user, pending);";
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
