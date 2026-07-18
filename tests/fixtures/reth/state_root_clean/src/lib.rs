// Clean fixture for `reth-state-root-mismatch-on-empty-block`.
//
// `compute_state_root` short-circuits on an empty block, returning the
// parent state root. Detector must NOT fire here.
#![allow(dead_code)]
#![allow(clippy::needless_return)]

pub struct Block {
    pub transactions: Vec<u8>,
    pub parent_state_root: [u8; 32],
}

pub struct StateDb;

impl StateDb {
    pub fn root(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

pub fn compute_state_root(db: &StateDb, block: &Block) -> [u8; 32] {
    if block.transactions.is_empty() {
        return block.parent_state_root;
    }
    let mut h = db.root();
    for byte in &block.transactions {
        h[0] ^= *byte;
    }
    h
}
