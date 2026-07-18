use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeStaking;
#[contractimpl]
impl SafeStaking {
    // OK: uses += to accumulate staked balance
    pub fn stake(user: u64, amount: u128) {
        staked_balance[user] += amount;
    }
}
#[allow(non_upper_case_globals)]
static mut staked_balance: [u128; 2] = [0, 0];
