struct RootRecord {
    root: [u8; 32],
    height: u32,
    chain_id: u32,
}

struct Proof;
struct ConsensusResult;

struct TrustedState;
struct PendingCache;

impl TrustedState {
    fn finalized_root(&self, _height: u32) -> Option<RootRecord> {
        None
    }

    fn is_finalized(&self, _height: u32) -> bool {
        true
    }
}

impl PendingCache {
    fn cached_root(&self, _height: u32) -> Option<RootRecord> {
        None
    }
}

fn verify_proof_against_root(_proof: &Proof, _root: &[u8; 32]) -> bool {
    true
}

fn validate_chain_context(record: &RootRecord, expected_height: u32, expected_chain_id: u32) -> bool {
    record.height == expected_height && record.chain_id == expected_chain_id
}

pub fn verify_consensus_proof_with_revalidated_pending_fallback(
    trusted_state: &TrustedState,
    pending_cache: &PendingCache,
    proof: &Proof,
    height: u32,
    expected_chain_id: u32,
) -> Result<ConsensusResult, &'static str> {
    let root = trusted_state
        .finalized_root(height)
        .or_else(|| pending_cache.cached_root(height))
        .ok_or("missing root")?;

    if !trusted_state.is_finalized(root.height) {
        return Err("unfinalized fallback root");
    }
    if !validate_chain_context(&root, height, expected_chain_id) {
        return Err("wrong chain context");
    }

    if verify_proof_against_root(proof, &root.root) {
        return Ok(ConsensusResult);
    }

    Err("bad proof")
}
