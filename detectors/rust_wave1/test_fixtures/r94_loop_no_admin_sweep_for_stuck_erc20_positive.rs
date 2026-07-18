// POSITIVE fixture: CollateralWrapper has wrap/unwrap path that
// custodies a token but ships no admin sweep/rescue fn — any
// token mistakenly sent to the program ATA is stuck.
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

    pub fn redeem(caller: u64, amount: u128) {
        token.safe_transfer(caller, amount);
    }
    // NOTE: no sweep / rescue / recover_erc20 / emergency_withdraw fn.
}

struct Token;
impl Token {
    fn safe_transfer(&self, _to: u64, _amount: u128) {}
    fn safe_transfer_from(&self, _from: u64, _to: u64, _amount: u128) {}
}
#[allow(non_upper_case_globals)]
static token: Token = Token;
#[allow(non_upper_case_globals)]
static this: u64 = 0;
