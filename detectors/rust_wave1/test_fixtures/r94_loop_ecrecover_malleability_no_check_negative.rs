const HALF_ORDER: [u8; 32] = [0x7f; 32];
use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeAccessToken;
#[contractimpl]
impl SafeAccessToken {
    // OK: checks s <= HALF_ORDER
    pub fn recover_signer(r: [u8; 32], s: [u8; 32], v: u8, msg: [u8; 32]) -> [u8; 20] {
        require(s <= HALF_ORDER);
        secp256k1::recover(&r, &s, v, &msg)
    }
}
mod secp256k1 {
    pub fn recover(_r: &[u8; 32], _s: &[u8; 32], _v: u8, _m: &[u8; 32]) -> [u8; 20] { [0; 20] }
}
fn require(_: bool) {}
