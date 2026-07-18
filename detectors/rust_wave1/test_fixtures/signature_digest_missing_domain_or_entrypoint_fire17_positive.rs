use soroban_sdk::{contract, contractimpl, Address};

#[contract]
pub struct ReplayableAuthorization;

#[contractimpl]
impl ReplayableAuthorization {
    // BUG: chain_id, entry_point, verifying_contract, and nonce are visible
    // replay-domain fields, but the signed digest only hashes signer and call.
    pub fn authorization_digest(
        signer: Address,
        call_hash: [u8; 32],
        chain_id: u64,
        entry_point: Address,
        verifying_contract: Address,
        nonce: u64,
    ) -> [u8; 32] {
        let _domain_fields_are_available = (
            chain_id,
            entry_point,
            verifying_contract,
            nonce,
        );
        let mut bytes = Vec::new();
        bytes.extend_from_slice(signer.as_ref());
        bytes.extend_from_slice(&call_hash);
        keccak256(&bytes)
    }
}

fn keccak256(_bytes: &[u8]) -> [u8; 32] {
    [0u8; 32]
}
