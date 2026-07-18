use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct SafeRewardVault {
    vault_balance: u128,
    reward_index: u128,
    collected_fees: u128,
}

#[contractimpl]
impl SafeRewardVault {
    pub fn distribute_rewards(&mut self, user_amount: u128, total_shares: u128, reward_rate: u128) {
        assert!(total_shares > 0);
        let payout = user_amount
            .checked_mul(reward_rate)
            .unwrap()
            .checked_div(total_shares)
            .unwrap();
        self.reward_index += payout;
        self.vault_balance -= payout;
    }

    pub fn set_fee_epochs(&mut self, emission_fee: u128, epochs: u128) {
        require!(epochs > 0);
        let fee_per_epoch = emission_fee / epochs;
        self.collected_fees += fee_per_epoch;
    }

    pub fn settle_position_fee(&mut self, position_size: u128, mark_price: u128, fee_bps: u128) {
        let notional = mul_div(position_size, mark_price, 1_000_000_000_000_000_000u128);
        let fee_due = mul_div(notional, fee_bps, 1_000_000_000_000_000_000u128);
        self.vault_balance -= fee_due;
        self.collected_fees += fee_due;
    }
}

fn mul_div(_a: u128, _b: u128, _d: u128) -> u128 {
    0
}
