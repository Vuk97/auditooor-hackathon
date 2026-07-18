use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: mints assets AND shares in lockstep
    pub fn distribute_reward(amount: u128, receiver: u64) {
        dusd.mint(vault_address(), amount);
        share_token.mint(receiver, amount);
    }
}
fn vault_address() -> u64 { 0 }
struct Dusd;
impl Dusd { fn mint(&self, _to: u64, _a: u128) {} }
#[allow(non_upper_case_globals)]
static dusd: Dusd = Dusd;
#[allow(non_upper_case_globals)]
static share_token: Dusd = Dusd;
