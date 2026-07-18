use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeSig;
#[contractimpl]
impl SafeSig {
    // OK: rejects high-s before ecrecover
    pub fn verify_sig(hash: u128, v: u8, r: u128, s: u128) -> u64 {
        require(s <= SECP256K1_N_DIV_2);
        let _ = (v, r, s);
        ecrecover(hash, v, r, s)
    }
}
fn ecrecover(_h: u128, _v: u8, _r: u128, _s: u128) -> u64 { 0 }
fn require(_c: bool) {}
const SECP256K1_N_DIV_2: u128 = 0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
