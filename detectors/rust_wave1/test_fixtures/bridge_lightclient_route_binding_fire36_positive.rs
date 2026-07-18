use std::collections::HashMap;

type Hash32 = [u8; 32];

#[derive(Clone, Copy)]
pub struct ClientId(u64);

#[derive(Clone, Copy)]
pub struct RouteId(u32);

#[derive(Clone, Copy)]
pub struct PalletId([u8; 32]);

pub struct StorageProof {
    pub key: Vec<u8>,
    pub value_hash: Hash32,
    pub nodes: Vec<Hash32>,
}

pub struct ProofKey {
    pub storage_key: Vec<u8>,
}

impl ProofKey {
    pub fn decode(_key: &[u8]) -> Result<Self, &'static str> {
        Ok(Self {
            storage_key: b"consensus-state".to_vec(),
        })
    }
}

pub struct LightClientRouter {
    client_roots: HashMap<(u64, u32), Hash32>,
    validator_sets: HashMap<u64, Hash32>,
}

impl LightClientRouter {
    pub fn verify_client_route_update(
        &mut self,
        chain_id: u32,
        client_id: ClientId,
        route_id: RouteId,
        pallet_id: PalletId,
        verifier_namespace: Hash32,
        proof: StorageProof,
        state_root: Hash32,
        validator_set_hash: Hash32,
    ) -> Result<(), &'static str> {
        let _route_context = (
            chain_id,
            client_id.0,
            route_id.0,
            pallet_id.0,
            verifier_namespace,
        );

        let proof_key = ProofKey::decode(&proof.key)?;
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&proof_key.storage_key);
        transcript.extend_from_slice(&proof.value_hash);
        transcript.extend_from_slice(&validator_set_hash);
        let signed_commitment = blake2b(&transcript);

        if !verify_membership(
            state_root,
            &proof_key.storage_key,
            &proof.value_hash,
            &proof.nodes,
            signed_commitment,
        ) {
            return Err("bad storage proof");
        }

        self.client_roots.insert((client_id.0, route_id.0), state_root);
        self.validator_sets.insert(client_id.0, validator_set_hash);
        Ok(())
    }
}

fn verify_membership(
    _root: Hash32,
    _key: &[u8],
    _value_hash: &Hash32,
    _nodes: &[Hash32],
    _signed_commitment: Hash32,
) -> bool {
    true
}

fn blake2b(_input: &[u8]) -> Hash32 {
    [0u8; 32]
}
