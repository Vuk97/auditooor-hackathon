use soroban_sdk::{contract, contractimpl};

pub struct Checkpoints;

impl Checkpoints {
    pub fn get_at_block(&self, _block: u64) -> u128 {
        0
    }
}

#[contract]
pub struct RewardsGauge;

#[contractimpl]
impl RewardsGauge {
    pub fn reward_weight_at_block(checkpoints: Checkpoints, block: u64) -> u128 {
        checkpoints.get_at_block(block)
    }

    pub fn claim_reward(user_balance: u128, reward_amount: u128) -> u128 {
        reward_amount * user_balance / total_supply()
    }

    pub fn stake(user: u64, amount: u128) {
        accrue_for_user(balance_of(user));
        let _ = amount;
    }
}

fn total_supply() -> u128 {
    1_000_000
}

fn accrue_for_user(_balance: u128) {}

fn balance_of(_user: u64) -> u128 {
    0
}
