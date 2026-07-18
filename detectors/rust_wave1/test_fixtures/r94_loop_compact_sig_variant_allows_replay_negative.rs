use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeECDSA;
#[contractimpl]
impl SafeECDSA {
    // OK: only accepts 65-byte canonical format
    pub fn recover(hash: u128, sig: [u8; 65]) -> u64 {
        if sig.len() != 65 { panic!("only canonical 65-byte"); }
        let _ = only_65_byte();
        secp_recover(hash, sig)
    }
}
fn only_65_byte() {}
fn secp_recover(_h: u128, _s: [u8; 65]) -> u64 { 0 }
