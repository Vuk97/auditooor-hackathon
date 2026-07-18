use std::collections::HashMap;

type Hash32 = [u8; 32];

#[derive(Clone, Copy)]
pub struct ClientNamespace(u64);

#[derive(Clone, Copy)]
pub struct RouteId(u32);

#[derive(Clone, Copy)]
pub struct PalletId([u8; 32]);

pub struct BeefyProof {
    pub payload_hash: Hash32,
    pub mmr_leaf_hash: Hash32,
    pub validator_set_root: Hash32,
    pub commitment_root: Hash32,
    pub signatures: Vec<Hash32>,
}

pub struct BeefyVerifier;

impl BeefyVerifier {
    pub fn verify_beefy_commitment(
        &self,
        _proof_digest: Hash32,
        _signatures: Vec<Hash32>,
    ) -> bool {
        true
    }
}

pub struct BeefyBridgeClient {
    accepted_commitments: HashMap<Hash32, Hash32>,
    validator_sets: HashMap<u64, Hash32>,
}

impl BeefyBridgeClient {
    pub fn submit_beefy_commitment(
        &mut self,
        source_chain_id: u32,
        destination_chain_id: u32,
        route_id: RouteId,
        pallet_id: PalletId,
        network_id: u32,
        client_namespace: ClientNamespace,
        proof: BeefyProof,
        verifier: &BeefyVerifier,
    ) -> Result<(), &'static str> {
        let _route_context = (
            source_chain_id,
            destination_chain_id,
            route_id.0,
            pallet_id.0,
            network_id,
            client_namespace.0,
        );

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&proof.payload_hash);
        transcript.extend_from_slice(&proof.mmr_leaf_hash);
        transcript.extend_from_slice(&proof.validator_set_root);
        transcript.extend_from_slice(&proof.commitment_root);
        let proof_digest = blake2_256(&transcript);

        if !verifier.verify_beefy_commitment(proof_digest, proof.signatures) {
            return Err("bad beefy commitment");
        }

        self.accepted_commitments
            .insert(proof_digest, proof.commitment_root);
        self.validator_sets
            .insert(client_namespace.0, proof.validator_set_root);
        Ok(())
    }
}

fn blake2_256(_input: &[u8]) -> Hash32 {
    [0u8; 32]
}
