use soroban_sdk::{contract, contractimpl, Env, Address};
#[contract]
pub struct SafeLaunchpad;
#[contractimpl]
impl SafeLaunchpad {
    // OK: decrements claimed_supply as well
    pub fn withdraw_tokens(env: Env, user: Address, amount: u128) {
        Self::set_user_shares(&env, user.clone(), 0u128);
        Self::set_has_claimed(&env, user, true);
        let mut claimed_supply = Self::get_claimed_supply(&env);
        claimed_supply -= amount;
        Self::set_claimed_supply(&env, claimed_supply);
        Self::refund_payment(&env, amount);
    }
}
impl SafeLaunchpad {
    fn set_user_shares(_e: &Env, _u: Address, _v: u128) {}
    fn set_has_claimed(_e: &Env, _u: Address, _v: bool) {}
    fn get_claimed_supply(_e: &Env) -> u128 { 0 }
    fn set_claimed_supply(_e: &Env, _v: u128) {}
    fn refund_payment(_e: &Env, _a: u128) {}
}
