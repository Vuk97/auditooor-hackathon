// Vuln fixture for `reth-state-root-mismatch-on-empty-block`.
//
// `compute_state_root` does NOT short-circuit on an empty-transactions
// block — it always recomputes the trie. Reth-shaped post-mortem:
// peer client returns parent state root for an empty block; we return
// a freshly hashed (but technically equal in some cases) root via the
// general path. A subtle refactor change can break this equality.
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

pub fn compute_state_root(db: &StateDb, _block: &Block) -> [u8; 32] {
    // BUG: no `if block.transactions.is_empty()` short-circuit.
    // We always recompute the trie. A bytecode-shape mismatch with the
    // peer client's empty-block path will desync canonical roots.
    let mut h = db.root();
    for byte in &_block.transactions {
        h[0] ^= *byte;
    }
    h
}
