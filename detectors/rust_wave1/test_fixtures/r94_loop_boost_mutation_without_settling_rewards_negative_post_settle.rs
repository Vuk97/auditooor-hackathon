use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Boost;

#[contractimpl]
impl Boost {
    pub fn set_boost(user: u64, new_boost: u128) {
        settle_reward(user);

        let mut boost_factor = 1_u128;
        boost_factor = new_boost;
        let _ = boost_factor;
    }
}

fn settle_reward(_u: u64) {}
