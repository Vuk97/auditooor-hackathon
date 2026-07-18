use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Staking;
#[contractimpl]
impl Staking {
    // BUG: staked_balance[user] = amount overwrites instead of += amount
    pub fn stake(user: u64, amount: u128) {
        let _ = user;
        staked_balance[user] = amount;
    }
}
#[allow(non_upper_case_globals)]
static mut staked_balance: [u128; 2] = [0, 0];
