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

fn is_pool_or_vault(_who: Address) -> bool {
    false
}

fn save_withdraw_credentials(_validator_id: u64, _credentials: Address) {}
fn eigenlayer_stake(_credentials: Address, _amount: u64) {}
fn load_current_credentials(_validator_id: u64) -> Address {
    [0; 20]
}
fn require_auth(_admin: &Address) {}
fn require(_ok: bool) {}

#[contract]
pub struct RewardSkew;

#[contractimpl]
impl RewardSkew {
    pub fn lock_reward(lock: &mut Lock, amount: u128) {
        require(lock.reward == 0);
        lock.reward = amount;
    }

    pub fn add_reward(lock: &mut Lock, amount: u128) {
        let previous_reward = lock.reward;
        lock.reward = previous_reward.saturating_add(amount);
    }

    pub fn pending_reward(token: Address, user: Address, pool: &Pool) -> u64 {
        if is_pool_or_vault(user) {
            return 0;
        }
        let deposit_principal = balance_of(token, user);
        deposit_principal * pool.acc_reward_per_share
    }

    pub fn stake(
        admin: Address,
        validator_id: u64,
        withdraw_credentials: Address,
        amount: u64,
    ) {
        require_auth(&admin);
        let current_creds = load_current_credentials(validator_id);
        assert!(current_creds == [0u8; 20], "withdrawal credentials already set");
        save_withdraw_credentials(validator_id, withdraw_credentials);
        eigenlayer_stake(withdraw_credentials, amount);
    }
}
