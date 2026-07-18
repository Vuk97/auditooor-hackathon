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
    pub chain_id: u32,
    pub client_id: u64,
    pub route_id: u32,
    pub pallet_id: Hash32,
    pub verifier_namespace: Hash32,
    pub storage_key: Vec<u8>,
}

impl ProofKey {
    pub fn decode(_key: &[u8]) -> Result<Self, &'static str> {
        Ok(Self {
            chain_id: 1,
            client_id: 7,
            route_id: 12,
            pallet_id: [1u8; 32],
            verifier_namespace: [2u8; 32],
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
        let proof_key = ProofKey::decode(&proof.key)?;
        ensure_eq!(proof_key.chain_id, chain_id)?;
        ensure_eq!(proof_key.client_id, client_id.0)?;
        ensure_eq!(proof_key.route_id, route_id.0)?;
        ensure_eq!(proof_key.pallet_id, pallet_id.0)?;
        ensure_eq!(proof_key.verifier_namespace, verifier_namespace)?;

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&chain_id.to_be_bytes());
        transcript.extend_from_slice(&client_id.0.to_be_bytes());
        transcript.extend_from_slice(&route_id.0.to_be_bytes());
        transcript.extend_from_slice(&pallet_id.0);
        transcript.extend_from_slice(&verifier_namespace);
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

macro_rules! ensure_eq {
    ($left:expr, $right:expr) => {
        if $left != $right {
            return Err("route binding mismatch");
        }
    };
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
