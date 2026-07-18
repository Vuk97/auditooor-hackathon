use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct RewardVault {
    vault_balance: u128,
    reward_index: u128,
    collected_fees: u128,
}

#[contractimpl]
impl RewardVault {
    pub fn distribute_rewards(&mut self, user_amount: u128, total_shares: u128, reward_rate: u128) {
        let payout = user_amount / total_shares * reward_rate;
        self.reward_index += payout;
        self.vault_balance -= payout;
    }

    pub fn set_fee_epochs(&mut self, emission_fee: u128, epochs: u128) {
        let fee_per_epoch = emission_fee / epochs;
        self.collected_fees += fee_per_epoch;
    }

    pub fn settle_position_fee(&mut self, position_size: u128, mark_price: u128, fee_bps: u128) {
        let fee_due = position_size * mark_price * fee_bps / 1_000_000_000_000_000_000u128;
        self.vault_balance -= fee_due;
        self.collected_fees += fee_due;
    }
}
