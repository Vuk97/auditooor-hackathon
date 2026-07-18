// Negative: every division has an upstream param-non-zero guard.

use soroban_sdk::{contract, contractimpl, Env};

pub enum Error { ZeroDivisor }

#[contract]
pub struct SafeGasCalc;

#[contractimpl]
impl SafeGasCalc {
    // OK: explicit require-equivalent before the division.
    pub fn calc_cost(env: Env, fee: u128, gas_price: u128) -> u128 {
        if gas_price == 0 {
            panic!("zero divisor");
        }
        fee / gas_price
    }

    // OK: require(gas_price > 0)-style guard.
    pub fn calc_cost2(env: Env, fee: u128, gas_price: u128) -> u128 {
        require(gas_price > 0);
        fee / gas_price
    }

    // OK: divisor is a constant, not a user param.
    pub fn halves(env: Env, fee: u128) -> u128 {
        fee / 2
    }

    // OK: divisor is self.field, not a param.
    pub fn using_state(&self, amount: u128) -> u128 {
        amount / self.scale
    }
}

fn require(_cond: bool) {}
