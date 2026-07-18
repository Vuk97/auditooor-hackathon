use soroban_sdk::{contract, contractimpl, Vec};

#[contract]
pub struct SafeBridgeVerifier;

#[contractimpl]
impl SafeBridgeVerifier {
    pub fn validator_set_checkpoint_hash(
        validator_set: Vec<u8>,
        checkpoint: u64,
        chain_id: u64,
        signatures: Vec<Vec<u8>>,
    ) -> [u8; 32] {
        sha256(&(chain_id, checkpoint, validator_set, signatures))
    }
}

fn sha256(_parts: &(u64, u64, Vec<u8>, Vec<Vec<u8>>)) -> [u8; 32] {
    [0u8; 32]
}
