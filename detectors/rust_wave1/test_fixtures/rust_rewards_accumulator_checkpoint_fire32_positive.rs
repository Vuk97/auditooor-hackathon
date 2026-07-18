use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

pub struct UserInfo {
    stake: u128,
    shares: u128,
    reward_debt: u128,
}

pub struct Pool {
    total_stake: u128,
    total_shares: u128,
    acc_reward_per_share: u128,
}

#[contract]
pub struct RewardVault {
    users: Vec<UserInfo>,
    pool: Pool,
}

#[contractimpl]
impl RewardVault {
    pub fn deposit_for_rewards(&mut self, user: usize, amount: u128) {
        self.users[user].stake += amount;
        self.users[user].shares += amount;
        self.pool.total_stake += amount;
        self.pool.total_shares += amount;

        self.update_global_accumulator();
        let owed = self.pending_reward(user);
        self.users[user].reward_debt = self.pool.acc_reward_per_share;
        self.credit_pending_reward(user, owed);
    }

    pub fn rotate_reward_debt_before_settle(&mut self, user: usize) {
        self.users[user].reward_debt = self.pool.acc_reward_per_share;
        self.settle_user_index(user);
    }

    fn pending_reward(&self, _user: usize) -> u128 {
        42
    }

    fn credit_pending_reward(&mut self, _user: usize, _amount: u128) {}

    fn update_global_accumulator(&mut self) {
        self.pool.acc_reward_per_share += 1;
    }

    fn settle_user_index(&mut self, _user: usize) {}
}

pub fn set_emission_per_second(vault: &mut RewardVault, rate: u128, supply: u128) {
    vault.pool.total_shares = supply;
    vault.update_global_accumulator();
    let _new_rate = rate;
}

pub fn safe_helper_not_pub_contract(_user: Address) {}
