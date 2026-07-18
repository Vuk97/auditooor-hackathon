pub struct BridgePacket {
    pub nonce: u64,
    pub source_channel_id: u32,
    pub payload_hash: [u8; 32],
}

pub struct CachedDomainVerifier {
    cached_chain_id: u64,
    cached_channel_id: u32,
    domain_separator: [u8; 32],
    verifying_contract: [u8; 20],
}

impl CachedDomainVerifier {
    pub fn new(chain_id: u64, channel_id: u32, verifying_contract: [u8; 20]) -> Self {
        let domain_separator = compute_domain_separator(chain_id, verifying_contract);
        Self {
            cached_chain_id: chain_id,
            cached_channel_id: channel_id,
            domain_separator: domain_separator,
            verifying_contract: verifying_contract,
        }
    }

    pub fn verify_permit(
        &self,
        owner: [u8; 20],
        spender: [u8; 20],
        amount: u128,
        signature: &[u8],
    ) -> bool {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.domain_separator);
        encoded.extend_from_slice(&self.cached_chain_id.to_be_bytes());
        encoded.extend_from_slice(&owner);
        encoded.extend_from_slice(&spender);
        encoded.extend_from_slice(&amount.to_be_bytes());
        let digest = keccak256(&encoded);
        recover_signer(&digest, signature) == owner
    }

    pub fn execute_bridge_message(
        &self,
        packet: BridgePacket,
        signer: [u8; 32],
        signature: &[u8],
    ) -> bool {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.cached_channel_id.to_be_bytes());
        encoded.extend_from_slice(&packet.nonce.to_be_bytes());
        encoded.extend_from_slice(&packet.payload_hash);
        let digest = sha256(&encoded);
        ed25519_verify(&signer, &digest, signature)
    }
}

fn compute_domain_separator(_chain_id: u64, _verifying_contract: [u8; 20]) -> [u8; 32] {
    [1u8; 32]
}

fn keccak256(_bytes: &[u8]) -> [u8; 32] {
    [2u8; 32]
}

fn sha256(_bytes: &[u8]) -> [u8; 32] {
    [3u8; 32]
}

fn recover_signer(_digest: &[u8; 32], _signature: &[u8]) -> [u8; 20] {
    [4u8; 20]
}

fn ed25519_verify(_signer: &[u8; 32], _digest: &[u8; 32], _signature: &[u8]) -> bool {
    true
}
