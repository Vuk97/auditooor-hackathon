use soroban_sdk::{contract, contractimpl, Env, Address};
#[contract]
pub struct Launchpad;
#[contractimpl]
impl Launchpad {
    // BUG: sets user's claimed = true but never decrements claimed_supply
    pub fn withdraw_tokens(env: Env, user: Address, amount: u128) {
        Self::set_user_shares(&env, user.clone(), 0u128);
        Self::set_has_claimed(&env, user, true);
        Self::refund_payment(&env, amount);
    }
}
impl Launchpad {
    fn set_user_shares(_e: &Env, _u: Address, _v: u128) {}
    fn set_has_claimed(_e: &Env, _u: Address, _v: bool) {}
    fn refund_payment(_e: &Env, _a: u128) {}
}
