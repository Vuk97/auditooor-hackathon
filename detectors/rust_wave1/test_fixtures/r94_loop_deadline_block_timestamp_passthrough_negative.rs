use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeSpell;
#[contractimpl]
impl SafeSpell {
    // OK: uses caller-supplied deadline, not block_timestamp
    pub fn swap(in_token: u64, out_token: u64, amount_in: u128, deadline: u64) -> u128 {
        curve.swap(in_token, out_token, amount_in, deadline);
        0
    }
}
struct Curve;
impl Curve { fn swap(&self, _i: u64, _o: u64, _a: u128, _d: u64) {} }
#[allow(non_upper_case_globals)]
static curve: Curve = Curve;
