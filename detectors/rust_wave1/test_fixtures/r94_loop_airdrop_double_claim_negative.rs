use soroban_sdk::{contract, contractimpl, Env, Address};
#[contract]
pub struct SafeAirdrop;
#[contractimpl]
impl SafeAirdrop {
    // OK: flag set BEFORE transfer (CEI)
    pub fn claim(env: Env, user: Address, amount: i128) {
        require(!Self::get_claimed(&env, &user));
        Self::set_claimed(&env, user.clone(), true);
        token::transfer(&env, user, amount);
    }
    // OK: mark_claimed helper before transfer
    pub fn claim_reward(env: Env, user: Address, amount: i128) {
        mark_claimed(&env, &user);
        token::transfer(&env, user, amount);
    }
}
impl SafeAirdrop {
    fn set_claimed(_e: &Env, _u: Address, _v: bool) {}
    fn get_claimed(_e: &Env, _u: &Address) -> bool { false }
}
fn mark_claimed(_e: &Env, _u: &Address) {}
fn require(_: bool) {}
mod token { pub fn transfer(_e: &super::Env, _u: super::Address, _a: i128) {} }
