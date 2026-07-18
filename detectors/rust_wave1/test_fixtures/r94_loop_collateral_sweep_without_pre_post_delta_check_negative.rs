// NEGATIVE fixture: Safe adapter measures pre/post delta and only
// transfers the measured received amount — no stranded-asset skim.
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct SafeCollateralAdapter;

#[contractimpl]
impl SafeCollateralAdapter {
    // OK: snapshot before, delta after, transfers only the delta.
    pub fn redeem_positions(caller: u64, amount: u128) {
        let balance_before = token.balance_of(this);
        ctf.redeem(amount);
        let received = token.balance_of(this) - balance_before;
        token.transfer(caller, received);
    }

    // OK: uses `delta =` explicitly.
    pub fn convert_positions(caller: u64, amount: u128) {
        let bal_before = token.balance_of(this);
        neg_risk.convert(amount);
        let delta = token.balance_of(this) - bal_before;
        token.transfer(caller, delta);
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
