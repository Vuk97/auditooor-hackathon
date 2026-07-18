pub struct Header {
    pub state_root: [u8; 32],
}

pub struct Block {
    pub header: Header,
    pub txs: Vec<Vec<u8>>,
}

pub struct Store;

impl Store {
    pub fn commit_root(&mut self, _root: [u8; 32]) {}
}

pub struct Executor {
    pub store: Store,
}

impl Executor {
    pub fn finalize_block(&mut self, block: Block) -> [u8; 32] {
        let computed_state_root = self.compute_state_root(&block.txs);

        // BUG: the locally computed root is ignored. A malicious or
        // invalid header root becomes the committed app hash.
        self.store.commit_root(block.header.state_root);
        block.header.state_root
    }

    fn compute_state_root(&self, _txs: &[Vec<u8>]) -> [u8; 32] {
        [7u8; 32]
    }
}
