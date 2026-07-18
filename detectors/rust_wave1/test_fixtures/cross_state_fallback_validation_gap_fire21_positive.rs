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
}

impl PendingCache {
    fn cached_root(&self, _height: u32) -> Option<RootRecord> {
        None
    }
}

fn verify_proof_against_root(_proof: &Proof, _root: &[u8; 32]) -> bool {
    true
}

pub fn verify_consensus_proof_with_pending_fallback(
    trusted_state: &TrustedState,
    pending_cache: &PendingCache,
    proof: &Proof,
    height: u32,
) -> Result<ConsensusResult, &'static str> {
    let root = trusted_state
        .finalized_root(height)
        .or_else(|| pending_cache.cached_root(height))
        .ok_or("missing root")?;

    if verify_proof_against_root(proof, &root.root) {
        return Ok(ConsensusResult);
    }

    Err("bad proof")
}

pub fn accept_header_after_non_finalized_fallback(
    non_finalized_chain_roots: &PendingCache,
    finalized_state: &TrustedState,
    proof: &Proof,
    height: u32,
) -> Result<ConsensusResult, &'static str> {
    let root = non_finalized_chain_roots
        .cached_root(height)
        .or_else(|| finalized_state.finalized_root(height))
        .ok_or("missing root")?;

    if verify_proof_against_root(proof, &root.root) {
        return Ok(ConsensusResult);
    }

    Err("bad proof")
}
