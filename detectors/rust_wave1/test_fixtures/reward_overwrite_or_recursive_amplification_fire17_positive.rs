use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

pub struct Lock {
    pub reward: u128,
}

pub struct Pool {
    pub acc_reward_per_share: u64,
}

fn balance_of(_token: Address, _who: Address) -> u64 {
    100_000
}

fn save_withdraw_credentials(_validator_id: u64, _credentials: Address) {}
fn eigenlayer_stake(_credentials: Address, _amount: u64) {}

#[contract]
pub struct RewardSkew;

#[contractimpl]
impl RewardSkew {
    pub fn lock_reward(lock: &mut Lock, amount: u128) {
        lock.reward = amount;
    }

    pub fn pending_reward(token: Address, user: Address, pool: &Pool) -> u64 {
        let bal = balance_of(token, user);
        bal * pool.acc_reward_per_share
    }

    pub fn stake(validator_id: u64, withdraw_credentials: Address, amount: u64) {
        save_withdraw_credentials(validator_id, withdraw_credentials);
        eigenlayer_stake(withdraw_credentials, amount);
    }
}
