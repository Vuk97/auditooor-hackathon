use std::collections::{HashMap, HashSet};

type Hash32 = [u8; 32];
type Address = [u8; 20];

const BRIDGE_TO_ADDRESS_DOMAIN_FIRE38: &[u8] = b"bridge-to-address-domain-fire38";

pub struct BridgeProof {
    pub payload_hash: Hash32,
    pub amount_commitment: Hash32,
    pub merkle_nodes: Vec<Hash32>,
}

pub struct BridgeRequest {
    pub to_address: Address,
    pub destination_chain_id: u32,
    pub source_chain_id: u32,
    pub lane_id: u32,
    pub channel_id: u32,
    pub source_commitment: Hash32,
    pub message_id: Hash32,
    pub amount: u128,
}

pub struct MerkleVerifier;

impl MerkleVerifier {
    pub fn verify_merkle_proof(
        &self,
        _proof_digest: Hash32,
        _source_commitment: Hash32,
        _nodes: Vec<Hash32>,
    ) -> bool {
        true
    }
}

pub struct DestinationBridge {
    processed_messages: HashSet<Hash32>,
    accepted_commitments: HashMap<Hash32, Hash32>,
}

impl DestinationBridge {
    pub fn finalize_bridge_transfer(
        &mut self,
        request: BridgeRequest,
        proof: BridgeProof,
        verifier: &MerkleVerifier,
    ) -> Result<(), &'static str> {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(BRIDGE_TO_ADDRESS_DOMAIN_FIRE38);
        transcript.extend_from_slice(&request.to_address);
        transcript.extend_from_slice(&request.destination_chain_id.to_be_bytes());
        transcript.extend_from_slice(&request.source_chain_id.to_be_bytes());
        transcript.extend_from_slice(&request.lane_id.to_be_bytes());
        transcript.extend_from_slice(&request.channel_id.to_be_bytes());
        transcript.extend_from_slice(&request.source_commitment);
        transcript.extend_from_slice(&request.message_id);
        transcript.extend_from_slice(&proof.payload_hash);
        transcript.extend_from_slice(&proof.amount_commitment);
        let proof_digest = blake2_256(&transcript);

        if !verifier.verify_merkle_proof(
            proof_digest,
            request.source_commitment,
            proof.merkle_nodes,
        ) {
            return Err("bad bridge proof");
        }

        self.processed_messages.insert(request.message_id);
        self.accepted_commitments
            .insert(request.source_commitment, proof.payload_hash);
        dispatch_to_address(request.to_address, request.amount);
        Ok(())
    }
}

fn dispatch_to_address(_to_address: Address, _amount: u128) {}

fn blake2_256(_input: &[u8]) -> Hash32 {
    [0u8; 32]
}
