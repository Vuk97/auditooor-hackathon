use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Wallet;
#[contractimpl]
impl Wallet {
    // BUG: recovers signer, no nonce check
    pub fn is_valid_signature(hash: u128, sig: u128) -> bool {
        let signer = env.crypto.secp256k1_recover(hash, sig);
        signer == owner()
    }
}
fn owner() -> u64 { 1 }
struct Env { crypto: Crypto }
struct Crypto;
impl Crypto { fn secp256k1_recover(&self, _h: u128, _s: u128) -> u64 { 0 } }
#[allow(non_upper_case_globals)]
static env: Env = Env { crypto: Crypto };
