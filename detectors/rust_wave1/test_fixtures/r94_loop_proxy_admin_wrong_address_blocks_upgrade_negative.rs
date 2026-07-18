use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeFactory;
#[contractimpl]
impl SafeFactory {
    // OK: passes a dedicated proxyAdmin contract as admin, not self
    pub fn create_proxy(impl_addr: u64, init_data: u128, proxy_admin_addr: u64) -> u64 {
        let _p = TransparentUpgradeableProxy::new(impl_addr, proxy_admin_addr);
        let _ = init_data;
        0
    }
}
struct TransparentUpgradeableProxy;
impl TransparentUpgradeableProxy { fn new(_i: u64, _a: u64) -> u64 { 0 } }
