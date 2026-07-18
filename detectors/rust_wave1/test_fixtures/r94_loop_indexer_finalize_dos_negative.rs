use soroban_sdk::{contract, contractimpl};
pub struct Block { pub txs: Vec<Vec<u8>> }
#[contract]
pub struct SafeIndexer;
#[contractimpl]
impl SafeIndexer {
    // OK: swallows per-tx parse errors
    pub fn listen_finalize_block(block: Block) {
        for tx in block.txs {
            if let Ok(_parsed) = Tx::try_from(tx) {
                // index it
            }
        }
    }
}
pub struct Tx;
impl TryFrom<Vec<u8>> for Tx {
    type Error = String;
    fn try_from(_v: Vec<u8>) -> Result<Self, String> { Ok(Tx) }
}
