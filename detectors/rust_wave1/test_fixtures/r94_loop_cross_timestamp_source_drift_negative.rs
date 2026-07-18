use soroban_sdk::{contract, contractimpl};
pub struct Pyth;
impl Pyth { pub fn publish_time(&self) -> u64 { 0 } }
pub struct Env;
impl Env { pub fn ledger(&self) -> Ledger { Ledger } }
pub struct Ledger;
impl Ledger { pub fn timestamp(&self) -> u64 { 0 } }
#[contract]
pub struct SafeOracle;
#[contractimpl]
impl SafeOracle {
    // OK: uses saturating_sub
    pub fn get_price(env: Env, pyth: Pyth) -> u64 {
        let age = env.ledger().timestamp().saturating_sub(pyth.publish_time());
        age
    }
}
