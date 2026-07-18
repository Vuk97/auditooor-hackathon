use soroban_sdk::{contract, contractimpl, Env, Address};
#[contract]
pub struct Airdrop;
#[contractimpl]
impl Airdrop {
    // BUG: transfers tokens with no claimed-flag at all
    pub fn claim(env: Env, user: Address, amount: i128) {
        token::transfer(&env, user, amount);
    }
    // BUG: sets flag AFTER transfer (re-entry window)
    pub fn claim_reward(env: Env, user: Address, amount: i128) {
        token::transfer(&env, user.clone(), amount);
        Self::set_claimed(&env, user, true);
    }
}
impl Airdrop { fn set_claimed(_e: &Env, _u: Address, _v: bool) {} }
mod token { pub fn transfer(_e: &super::Env, _u: super::Address, _a: i128) {} }
