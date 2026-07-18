use std::collections::HashMap;

type Hash32 = [u8; 32];

#[derive(Clone, Copy)]
pub struct ClientNamespace(u64);

#[derive(Clone, Copy)]
pub struct ValidatorSet {
    pub id: u64,
    pub root: Hash32,
    pub len: u32,
}

pub struct BeefyValidatorProof {
    pub signed_commitment_hash: Hash32,
    pub mmr_root: Hash32,
    pub commitment_root: Hash32,
    pub signatures: Vec<Hash32>,
}

pub struct BeefyVerifier;

impl BeefyVerifier {
    pub fn verify_validator_set_update(
        &self,
        _proof_digest: Hash32,
        _signatures: Vec<Hash32>,
    ) -> bool {
        true
    }
}

pub struct BeefyBridgeClient {
    current_validator_set_id: u64,
    validator_sets: HashMap<u64, Hash32>,
    validator_set_lengths: HashMap<u64, u32>,
}

impl BeefyBridgeClient {
    pub fn submit_beefy_validator_set_update(
        &mut self,
        source_chain_id: u32,
        destination_chain_id: u32,
        client_namespace: ClientNamespace,
        current_set: ValidatorSet,
        next_set: ValidatorSet,
        proof: BeefyValidatorProof,
        verifier: &BeefyVerifier,
    ) -> Result<(), &'static str> {
        let _visible_validator_domain = (
            source_chain_id,
            destination_chain_id,
            client_namespace.0,
            current_set.id,
            current_set.root,
            current_set.len,
            next_set.id,
            next_set.root,
            next_set.len,
        );

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&proof.signed_commitment_hash);
        transcript.extend_from_slice(&proof.mmr_root);
        transcript.extend_from_slice(&proof.commitment_root);
        let proof_digest = blake2_256(&transcript);

        if !verifier.verify_validator_set_update(proof_digest, proof.signatures) {
            return Err("bad beefy validator proof");
        }

        self.validator_sets.insert(next_set.id, next_set.root);
        self.validator_set_lengths.insert(next_set.id, next_set.len);
        self.current_validator_set_id = next_set.id;
        Ok(())
    }
}

fn blake2_256(_input: &[u8]) -> Hash32 {
    [0u8; 32]
}
