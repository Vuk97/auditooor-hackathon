use soroban_sdk::{contract, contractimpl};
pub struct Block { pub txs: Vec<Vec<u8>> }
#[contract]
pub struct Indexer;
#[contractimpl]
impl Indexer {
    // BUG: iterates txs, per-tx parse with ?, no swallow
    pub fn listen_finalize_block(block: Block) -> Result<(), String> {
        for tx in block.txs {
            let _parsed: Tx = Tx::try_from(tx)?;
        }
        Ok(())
    }
}
pub struct Tx;
impl TryFrom<Vec<u8>> for Tx {
    type Error = String;
    fn try_from(_v: Vec<u8>) -> Result<Self, String> { Ok(Tx) }
}
