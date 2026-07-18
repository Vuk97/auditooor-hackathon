use std::collections::HashSet;

type Hash32 = [u8; 32];
type AppDomain = [u8; 32];

pub struct Signature;
pub struct Validator;

pub struct BridgeRouter {
    processed_messages: HashSet<Hash32>,
}

impl BridgeRouter {
    pub fn process_bridge_payload(
        &mut self,
        source_chain: u32,
        destination_chain: u32,
        endpoint_id: u16,
        receiver_app: AppDomain,
        nonce: u64,
        payload_hash: Hash32,
        attestation: Signature,
    ) -> Result<(), &'static str> {
        if !verify_attestation(payload_hash, &attestation) {
            return Err("bad attestation");
        }

        let mut replay_material = Vec::new();
        replay_material.extend_from_slice(&source_chain.to_be_bytes());
        replay_material.extend_from_slice(&destination_chain.to_be_bytes());
        replay_material.extend_from_slice(&endpoint_id.to_be_bytes());
        replay_material.extend_from_slice(&receiver_app);
        replay_material.extend_from_slice(&nonce.to_be_bytes());
        replay_material.extend_from_slice(&payload_hash);
        let replay_key = sha256(&replay_material);

        if self.processed_messages.contains(&replay_key) {
            return Err("replay");
        }
        self.processed_messages.insert(replay_key);
        self.release_to(receiver_app, payload_hash);
        Ok(())
    }

    pub fn verify_bridge_attestation_signature(
        &self,
        source_chain: u32,
        destination_chain: u32,
        channel_id: u32,
        receiver_app: AppDomain,
        payload_hash: Hash32,
        validator: &Validator,
        signature: &Signature,
    ) -> bool {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&source_chain.to_be_bytes());
        transcript.extend_from_slice(&destination_chain.to_be_bytes());
        transcript.extend_from_slice(&channel_id.to_be_bytes());
        transcript.extend_from_slice(&receiver_app);
        transcript.extend_from_slice(&payload_hash);
        let digest = blake2b(&transcript);
        verify_signature(validator, &digest, signature)
    }

    fn release_to(&mut self, _receiver_app: AppDomain, _payload_hash: Hash32) {}
}

fn verify_attestation(_payload_hash: Hash32, _attestation: &Signature) -> bool {
    true
}

fn verify_signature(_validator: &Validator, _digest: &Hash32, _signature: &Signature) -> bool {
    true
}

fn sha256(_bytes: &[u8]) -> Hash32 {
    [0u8; 32]
}

fn blake2b(_bytes: &[u8]) -> Hash32 {
    [0u8; 32]
}
