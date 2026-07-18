// NEGATIVE fixture: Same wrap/unwrap path but ships an explicit
// admin-gated sweep fn for stuck tokens — finding is defused.
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct CollateralWrapper;

#[contractimpl]
impl CollateralWrapper {
    pub fn wrap(caller: u64, amount: u128) {
        token.safe_transfer_from(caller, this, amount);
    }

    pub fn unwrap(caller: u64, amount: u128) {
        token.safe_transfer(caller, amount);
    }

    // OK: admin sweep exposed — stuck tokens can be recovered.
    pub fn sweep(admin: u64, to: u64, amount: u128) {
        assert!(admin == ADMIN);
        token.safe_transfer(to, amount);
    }
}

const ADMIN: u64 = 1;
struct Token;
impl Token {
    fn safe_transfer(&self, _to: u64, _amount: u128) {}
    fn safe_transfer_from(&self, _from: u64, _to: u64, _amount: u128) {}
}
#[allow(non_upper_case_globals)]
static token: Token = Token;
#[allow(non_upper_case_globals)]
static this: u64 = 0;
