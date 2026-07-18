use soroban_sdk::{contract, contractimpl};

#[derive(Clone)]
pub struct UserReward {
    reward_debt: u128,
    claimed: bool,
    multiplier: u128,
}

pub struct Pool {
    acc_reward_per_share: u128,
}

#[contract]
pub struct SkewedRewards {
    users: Vec<UserReward>,
    pool: Pool,
    total_reward_debt: u128,
}

#[contractimpl]
impl SkewedRewards {
    pub fn claim_reward(&mut self, user: usize, emergency: bool) -> u128 {
        if emergency {
            let owed = self.pending_reward(user);
            self.users[user].reward_debt = self.pool.acc_reward_per_share;
            self.users[user].claimed = true;
            self.users[user].multiplier = 1;
            self.transfer_reward(user, owed);
            owed
        } else {
            self.update_global_accumulator();
            let owed = self.pending_reward(user);
            self.total_reward_debt += owed;
            self.users[user].reward_debt = self.pool.acc_reward_per_share;
            self.transfer_reward(user, owed);
            owed
        }
    }

    fn pending_reward(&self, _user: usize) -> u128 {
        42
    }

    fn transfer_reward(&self, _user: usize, _amount: u128) {}

    fn update_global_accumulator(&mut self) {
        self.pool.acc_reward_per_share += 1;
    }
}

impl SkewedRewards {
    fn new() -> Self {
        Self {
            users: vec![
                UserReward {
                    reward_debt: 0,
                    claimed: false,
                    multiplier: 2,
                },
            ],
            pool: Pool {
                acc_reward_per_share: 10,
            },
            total_reward_debt: 0,
        }
    }
}
