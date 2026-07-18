use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Gateway;
#[contractimpl]
impl Gateway {
    // BUG: mints `amount` based on caller's input without measuring delta
    pub fn fund(user: u64, amount: u128) {
        token.safe_transfer_from(user, this, amount);
        mint_shares(user, amount);
    }
}
fn mint_shares(_u: u64, _a: u128) {}
#[allow(non_upper_case_globals)]
static this: u64 = 0;
struct Token;
impl Token { fn safe_transfer_from(&self, _f: u64, _t: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static token: Token = Token;
