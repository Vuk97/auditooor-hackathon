use soroban_sdk::{contract, contractimpl, Address};

#[contract]
pub struct BoundAuthorization;

#[contractimpl]
impl BoundAuthorization {
    // OK: every replay-domain field is included in the signed digest.
    pub fn authorization_digest(
        signer: Address,
        call_hash: [u8; 32],
        chain_id: u64,
        entry_point: Address,
        verifying_contract: Address,
        nonce: u64,
    ) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(signer.as_ref());
        bytes.extend_from_slice(&call_hash);
        bytes.extend_from_slice(&chain_id.to_be_bytes());
        bytes.extend_from_slice(entry_point.as_ref());
        bytes.extend_from_slice(verifying_contract.as_ref());
        bytes.extend_from_slice(&nonce.to_be_bytes());
        keccak256(&bytes)
    }
}

fn keccak256(_bytes: &[u8]) -> [u8; 32] {
    [0u8; 32]
}
