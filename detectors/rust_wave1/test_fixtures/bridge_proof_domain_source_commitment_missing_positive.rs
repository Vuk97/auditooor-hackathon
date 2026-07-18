pub struct HeadProof {
    pub pos: u64,
    pub width: u64,
    pub proof: Vec<[u8; 32]>,
}

pub struct SourceProof {
    pub head_proof: HeadProof,
    pub unbound_parachain_head_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub leaf_proof: Vec<[u8; 32]>,
    pub leaf_order: u64,
}

pub struct BeefyClient;

impl BeefyClient {
    pub fn verify_mmr_leaf_proof(
        &self,
        _leaf_hash: [u8; 32],
        _proof: Vec<[u8; 32]>,
        _order: u64,
    ) -> bool {
        true
    }
}

pub struct BridgeSourceCommitmentVerifier;

impl BridgeSourceCommitmentVerifier {
    pub fn verify_bridge_source_commitment(
        beefy_client: &BeefyClient,
        encoded_para_id: [u8; 4],
        commitment: [u8; 32],
        proof: SourceProof,
    ) -> bool {
        let _ = encoded_para_id;
        let _ = commitment;

        let parachain_heads_root = compute_root(
            proof.unbound_parachain_head_hash,
            proof.head_proof.pos,
            proof.head_proof.width,
            proof.head_proof.proof,
        );
        let leaf_hash = create_mmr_leaf(proof.parent_hash, parachain_heads_root);

        beefy_client.verify_mmr_leaf_proof(leaf_hash, proof.leaf_proof, proof.leaf_order)
    }
}

fn compute_root(
    _leaf: [u8; 32],
    _pos: u64,
    _width: u64,
    _proof: Vec<[u8; 32]>,
) -> [u8; 32] {
    [0u8; 32]
}

fn create_mmr_leaf(_parent_hash: [u8; 32], _parachain_heads_root: [u8; 32]) -> [u8; 32] {
    [0u8; 32]
}
