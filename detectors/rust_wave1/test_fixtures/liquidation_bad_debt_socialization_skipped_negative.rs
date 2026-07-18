use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // SAFE: bad-debt branch writes to bad_debt accumulator
    pub fn liquidate(env: Env, borrower: Address, debt: i128, collateral: i128) -> i128 {
        if collateral < debt {
            let deficit = debt - collateral;
            record_bad_debt(&env, &borrower, deficit);
            return collateral;
        }
        debt
    }
}

fn record_bad_debt(_: &Env, _: &Address, _: i128) {}
