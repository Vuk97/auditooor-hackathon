use soroban_sdk::{contract, contractimpl};

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
        self.update_global_accumulator();
        self.settle_user_index(user);
        let owed = self.pending_reward(user);
        self.credit_pending_reward(user, owed);

        self.users[user].stake += amount;
        self.users[user].shares += amount;
        self.pool.total_stake += amount;
        self.pool.total_shares += amount;
        self.users[user].reward_debt = self.pool.acc_reward_per_share;
    }

    pub fn checkpoint_user_rewards(&mut self, user: usize) {
        let owed = self.pending_reward(user);
        self.credit_pending_reward(user, owed);
        self.users[user].reward_debt = self.pool.acc_reward_per_share;
    }

    pub fn set_emission_per_second(&mut self, rate: u128, supply: u128) {
        self.update_global_accumulator();
        self.pool.total_shares = supply;
        let _new_rate = rate;
    }

    pub fn string_bait(&mut self) {
        let _bait = "self.users[user].reward_debt = self.pool.acc_reward_per_share; update_global_accumulator()";
        self.update_global_accumulator();
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
