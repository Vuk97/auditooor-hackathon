use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Factory;
#[contractimpl]
impl Factory {
    // BUG: passes address(this) as admin to TransparentUpgradeableProxy
    pub fn create_proxy(impl_addr: u64, init_data: u128) -> u64 {
        let _p = TransparentUpgradeableProxy::new(impl_addr, address_of(self));
        let _ = init_data;
        0
    }
}
fn address_of(_v: u64) -> u64 { 0 }
#[allow(non_upper_case_globals)]
static self: u64 = 0;
struct TransparentUpgradeableProxy;
impl TransparentUpgradeableProxy { fn new(_i: u64, _a: u64) -> u64 { 0 } }
