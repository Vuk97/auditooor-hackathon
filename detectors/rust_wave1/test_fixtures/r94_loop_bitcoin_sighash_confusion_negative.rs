use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBtcSigner;
#[contractimpl]
impl SafeBtcSigner {
    // OK: consistent CalcWitnessSigHashV0 only
    pub fn sign_btc(tx: Vec<u8>, idx: u32, amount: u64) -> Vec<u8> {
        CalcWitnessSigHashV0(tx, idx, amount)
    }
    pub fn compute_sighash(tx: Vec<u8>, idx: u32, amount: u64) -> Vec<u8> {
        CalcWitnessSigHashV0(tx, idx, amount)
    }
}
fn CalcWitnessSigHashV0(_t: Vec<u8>, _i: u32, _a: u64) -> Vec<u8> { vec![] }
