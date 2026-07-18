use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeWrapper;
#[contractimpl]
impl SafeWrapper {
    // OK: collects fees before transferring NFT
    pub fn unwrap(from: u64, to: u64, token_id: u64, amount: u128) {
        collect_fees(token_id);
        burn_shares(from, token_id, amount);
        underlying.transfer_from(from, to, token_id);
    }
}
fn collect_fees(_t: u64) {}
fn burn_shares(_f: u64, _t: u64, _a: u128) {}
struct Underlying;
impl Underlying { fn transfer_from(&self, _f: u64, _t: u64, _i: u64) {} }
#[allow(non_upper_case_globals)]
static underlying: Underlying = Underlying;
