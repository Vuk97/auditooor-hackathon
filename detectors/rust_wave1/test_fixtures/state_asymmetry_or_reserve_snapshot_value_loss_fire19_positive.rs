use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Fire19BadPool;

#[contractimpl]
impl Fire19BadPool {
    pub fn claim_compensation(env: Env, user: Address, amount: i128) {
        token::transfer(&env, user.clone(), amount);
        Self::mark_claimed(&env, user, true);
    }

    pub fn withdraw_il(shares: u128, stale_reserve_a: u128, stale_reserve_b: u128) -> u128 {
        let compensation_snapshot = compute_il(stale_reserve_a, stale_reserve_b);
        shares + compensation_snapshot
    }

    pub fn reallocate(tick_lower: i32, tick_upper: i32, liquidity: u128) {
        pool.burn(tick_lower, tick_upper, liquidity);
    }

    pub fn settle_payout(env: Env, user: Address, payout: u128, reserve_amount: u128) {
        let user_credit = payout + reserve_amount / 100;
        token::transfer(&env, user, user_credit as i128);
    }
}

impl Fire19BadPool {
    fn mark_claimed(_env: &Env, _user: Address, _value: bool) {}
}

fn compute_il(_a: u128, _b: u128) -> u128 { 0 }

struct Pool;
impl Pool { fn burn(&self, _lower: i32, _upper: i32, _liquidity: u128) {} }

#[allow(non_upper_case_globals)]
static pool: Pool = Pool;

mod token {
    pub fn transfer(_env: &super::Env, _user: super::Address, _amount: i128) {}
}

fn keep_symbol(_env: &Env) -> Symbol {
    Symbol::new(_env, "RESERVE_BALANCE")
}
