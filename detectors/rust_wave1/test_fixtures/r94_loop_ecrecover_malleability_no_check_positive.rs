use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct AccessToken;
#[contractimpl]
impl AccessToken {
    // BUG: ecrecover / secp256k1_recover with no s-bound check
    pub fn recover_signer(r: [u8; 32], s: [u8; 32], v: u8, msg: [u8; 32]) -> [u8; 20] {
        secp256k1::recover(&r, &s, v, &msg)
    }
}
mod secp256k1 {
    pub fn recover(_r: &[u8; 32], _s: &[u8; 32], _v: u8, _m: &[u8; 32]) -> [u8; 20] { [0; 20] }
}
