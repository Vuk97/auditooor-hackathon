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
    pub fn finalize_block(&mut self, block: Block) -> Result<[u8; 32], &'static str> {
        let computed_state_root = self.compute_state_root(&block.txs);

        if computed_state_root != block.header.state_root {
            return Err("state root mismatch");
        }

        self.store.commit_root(computed_state_root);
        Ok(computed_state_root)
    }

    fn compute_state_root(&self, _txs: &[Vec<u8>]) -> [u8; 32] {
        [7u8; 32]
    }
}
