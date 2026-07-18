// POSITIVE fixture: Soroban-style CtfCollateralAdapter sweeps full
// balance to caller after redeem without pre/post delta.
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct CtfCollateralAdapter;

#[contractimpl]
impl CtfCollateralAdapter {
    // BUG: redeem + full-balance sweep, no balance_before snapshot.
    pub fn redeem_positions(caller: u64, amount: u128) {
        ctf.redeem(amount);
        // Sweeps the entire program-owned USDC.e balance to caller.
        token.transfer(caller, token.balance_of(this));
    }

    // Another sibling: convert_positions, same shape.
    pub fn convert_positions(caller: u64, amount: u128) {
        neg_risk.convert(amount);
        token.transfer(caller, token.balance_of(this));
    }
}

#[allow(non_upper_case_globals)]
static this: u64 = 0;
struct Token;
impl Token {
    fn transfer(&self, _to: u64, _amount: u128) {}
    fn balance_of(&self, _a: u64) -> u128 { 0 }
}
struct Ctf;
impl Ctf { fn redeem(&self, _a: u128) {} }
struct NegRisk;
impl NegRisk { fn convert(&self, _a: u128) {} }
#[allow(non_upper_case_globals)]
static token: Token = Token;
#[allow(non_upper_case_globals)]
static ctf: Ctf = Ctf;
#[allow(non_upper_case_globals)]
static neg_risk: NegRisk = NegRisk;
