use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeProxy;
#[contractimpl]
impl SafeProxy {
    // OK: builds witness hash binding recipient and calls witness variant
    pub fn permit_transfer(to: u64, amount: u128, sig: [u8; 65]) {
        let w = witness_hash(to, amount);
        permit2.permit_witness_transfer_from(to, amount, w, sig);
    }
}
fn witness_hash(_t: u64, _a: u128) -> u128 { 0 }
struct Permit2;
impl Permit2 { fn permit_witness_transfer_from(&self, _t: u64, _a: u128, _w: u128, _s: [u8; 65]) {} }
#[allow(non_upper_case_globals)]
static permit2: Permit2 = Permit2;
