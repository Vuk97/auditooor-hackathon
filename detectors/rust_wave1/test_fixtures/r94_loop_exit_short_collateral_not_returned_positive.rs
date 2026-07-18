use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Facet;
#[contractimpl]
impl Facet {
    // BUG: transfers payout but doesn't return collateral
    pub fn exit_short(user: u64, payout: u128, collateral: u128) {
        token.transfer(user, payout);
        let _ = collateral;
    }
}
struct Token;
impl Token { fn transfer(&self, _to: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static token: Token = Token;
