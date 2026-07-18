use soroban_sdk::{contract, contractimpl};

pub struct Checkpoints;

impl Checkpoints {
    pub fn get_at_block(&self, _block: u64) -> u128 {
        0
    }
}

#[contract]
pub struct SafeRewardsGauge;

#[contractimpl]
impl SafeRewardsGauge {
    pub fn reward_weight_at_block(
        checkpoints: Checkpoints,
        block: u64,
        checkpoint_index: u32,
    ) -> u128 {
        checkpoints.get_at_block(block) + checkpoint_index as u128
    }

    pub fn claim_reward(user_balance: u128, reward_amount: u128) -> u128 {
        reward_amount * user_balance / eligible_supply()
    }

    pub fn stake(user: u64, amount: u128) {
        let weight = time_weighted_balance(user);
        accrue_for_user(weight);
        let _ = amount;
    }
}

fn eligible_supply() -> u128 {
    500_000
}

fn accrue_for_user(_balance: u128) {}

fn time_weighted_balance(_user: u64) -> u128 {
    0
}
