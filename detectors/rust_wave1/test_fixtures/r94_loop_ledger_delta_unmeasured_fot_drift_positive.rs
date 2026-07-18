use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Lender;
#[contractimpl]
impl Lender {
    // BUG: ledger += amount without balance-delta measurement
    pub fn deposit(user: u64, amount: u128) {
        token.safe_transfer_from(user, this, amount);
        let mut total_deposits = 0u128;
        total_deposits += amount;
        let _ = total_deposits;
    }
}
#[allow(non_upper_case_globals)]
static this: u64 = 0;
struct Token;
impl Token { fn safe_transfer_from(&self, _f: u64, _t: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static token: Token = Token;
