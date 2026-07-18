use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct BtcSigner;
#[contractimpl]
impl BtcSigner {
    // BUG: mixes witness + legacy sighash computations in one signer path
    pub fn sign_btc(tx: Vec<u8>, idx: u32, amount: u64) -> Vec<u8> {
        let wh = CalcWitnessSigHashV0(tx.clone(), idx, amount);
        let lh = CalcSignatureHash(tx, idx);
        [wh, lh].concat()
    }
}
fn CalcWitnessSigHashV0(_t: Vec<u8>, _i: u32, _a: u64) -> Vec<u8> { vec![] }
fn CalcSignatureHash(_t: Vec<u8>, _i: u32) -> Vec<u8> { vec![] }
