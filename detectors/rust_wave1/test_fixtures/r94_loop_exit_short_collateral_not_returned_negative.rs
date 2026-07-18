use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeFacet;
#[contractimpl]
impl SafeFacet {
    // OK: transfers payout AND collateral back to user
    pub fn exit_short(user: u64, payout: u128, collateral: u128) {
        token.transfer(user, payout);
        token.transfer(user, collateral);
    }
}
struct Token;
impl Token { fn transfer(&self, _to: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static token: Token = Token;
