use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeGateway;
#[contractimpl]
impl SafeGateway {
    // OK: measures balance delta after transfer, mints actual received
    pub fn fund(user: u64, amount: u128) {
        let balance_before = balance_of(this);
        token.safe_transfer_from(user, this, amount);
        let received = balance_of(this) - balance_before;
        mint_shares(user, received);
    }
}
fn mint_shares(_u: u64, _a: u128) {}
fn balance_of(_a: u64) -> u128 { 0 }
#[allow(non_upper_case_globals)]
static this: u64 = 0;
struct Token;
impl Token { fn safe_transfer_from(&self, _f: u64, _t: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static token: Token = Token;
