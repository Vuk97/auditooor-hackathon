use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeWallet;
#[contractimpl]
impl SafeWallet {
    // OK: checks + bumps used_sigs map after recovery
    pub fn is_valid_signature(hash: u128, sig: u128) -> bool {
        if used_sigs().contains(hash) { return false; }
        let signer = env.crypto.secp256k1_recover(hash, sig);
        used_sigs().insert(hash);
        signer == owner()
    }
}
fn owner() -> u64 { 1 }
fn used_sigs() -> Used { Used }
struct Used;
impl Used {
    fn contains(&self, _h: u128) -> bool { false }
    fn insert(&self, _h: u128) {}
}
struct Env { crypto: Crypto }
struct Crypto;
impl Crypto { fn secp256k1_recover(&self, _h: u128, _s: u128) -> u64 { 0 } }
#[allow(non_upper_case_globals)]
static env: Env = Env { crypto: Crypto };
