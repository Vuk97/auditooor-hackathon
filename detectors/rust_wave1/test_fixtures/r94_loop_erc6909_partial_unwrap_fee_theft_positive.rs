use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Wrapper;
#[contractimpl]
impl Wrapper {
    // BUG: partial unwrap transfers whole NFT without collecting fees first
    pub fn unwrap(from: u64, to: u64, token_id: u64, amount: u128) {
        burn_shares(from, token_id, amount);
        underlying.transfer_from(from, to, token_id);
    }
}
fn burn_shares(_f: u64, _t: u64, _a: u128) {}
struct Underlying;
impl Underlying { fn transfer_from(&self, _f: u64, _t: u64, _i: u64) {} }
#[allow(non_upper_case_globals)]
static underlying: Underlying = Underlying;
