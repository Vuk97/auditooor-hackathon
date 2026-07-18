use soroban_sdk::{contract, contractimpl};
pub struct Vaa { pub signatures: Vec<[u8; 65]>, pub payload: Vec<u8> }
#[contract]
pub struct Bridge;
#[contractimpl]
impl Bridge {
    // BUG: reads vaa.signatures but no quorum check
    pub fn verify_vaa(vaa: Vaa) -> bool {
        for sig in &vaa.signatures {
            let _ = sig;
        }
        !vaa.payload.is_empty()
    }
    // BUG 2: no quorum threshold either
    pub fn complete_transfer(vaa: Vaa) {
        let _ = vaa.signatures.len();
    }
}
