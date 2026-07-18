use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Proxy;
#[contractimpl]
impl Proxy {
    // BUG: calls permit_transfer_from without witness intent binding
    pub fn permit_transfer(to: u64, amount: u128, sig: [u8; 65]) {
        permit2.permit_transfer_from(to, amount, sig);
    }
}
struct Permit2;
impl Permit2 { fn permit_transfer_from(&self, _to: u64, _a: u128, _s: [u8; 65]) {} }
#[allow(non_upper_case_globals)]
static permit2: Permit2 = Permit2;
