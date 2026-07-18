use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeStaking;
#[contractimpl]
impl SafeStaking {
    // OK: decrements staked_balance[user] -= amount before transfer
    pub fn unstake(user: u64, amount: u128) {
        staked_balance[user] -= amount;
        token.transfer(user, amount);
    }
}
struct Token;
impl Token { fn transfer(&self, _to: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static token: Token = Token;
#[allow(non_upper_case_globals)]
static mut staked_balance: [u128; 2] = [0, 0];
