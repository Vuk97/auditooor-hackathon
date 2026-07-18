use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLender;
#[contractimpl]
impl SafeLender {
    // OK: measures balance delta before adjusting ledger
    pub fn deposit(user: u64, amount: u128) {
        let balance_before = balance_of(this);
        token.safe_transfer_from(user, this, amount);
        let delta = balance_of(this) - balance_before;
        let mut total_deposits = 0u128;
        total_deposits += delta;
        let _ = total_deposits;
    }
}
fn balance_of(_a: u64) -> u128 { 0 }
#[allow(non_upper_case_globals)]
static this: u64 = 0;
struct Token;
impl Token { fn safe_transfer_from(&self, _f: u64, _t: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static token: Token = Token;
