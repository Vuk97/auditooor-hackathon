use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Staking;
#[contractimpl]
impl Staking {
    // BUG: transfers out without decrementing staked_balance
    pub fn unstake(user: u64, amount: u128) {
        token.transfer(user, amount);
    }
}
struct Token;
impl Token { fn transfer(&self, _to: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static token: Token = Token;
