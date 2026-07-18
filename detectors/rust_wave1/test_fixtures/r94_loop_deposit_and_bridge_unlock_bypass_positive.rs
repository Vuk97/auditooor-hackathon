use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: mints shares then bridges them out, no share_unlock_time check
    pub fn deposit_and_bridge(assets: u128, dest: u64) -> u128 {
        let shares = preview_deposit(assets);
        self_.mint(receiver(), shares);
        bridge.send(dest, shares);
        shares
    }
}
fn preview_deposit(_a: u128) -> u128 { 0 }
fn receiver() -> u64 { 0 }
struct SelfObj;
impl SelfObj { fn mint(&self, _to: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static self_: SelfObj = SelfObj;
struct Bridge;
impl Bridge { fn send(&self, _d: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static bridge: Bridge = Bridge;
