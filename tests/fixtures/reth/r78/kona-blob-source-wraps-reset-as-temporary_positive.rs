// Pre-fix: kona/crates/protocol/derive/src/sources/blobs.rs#L119-L122 at 9eaad92.
// Optimism issue 19354.

#![allow(dead_code, unused_variables)]

#[derive(Debug)]
pub enum AlloyChainProviderError {
    BlockNotFound([u8; 32]),
    Other,
}

impl core::fmt::Display for AlloyChainProviderError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result { write!(f, "{:?}", self) }
}

#[derive(Debug)]
pub enum BlobProviderError { Backend(String) }

#[derive(Debug)]
pub enum PipelineErrorKind {
    Temporary(BlobProviderError),
    Reset,
}

pub struct ChainProvider;
pub struct BlockRef { pub hash: [u8; 32] }
pub struct BlockInfoTxs;

impl ChainProvider {
    pub fn block_info_and_transactions_by_hash(
        &self,
        _h: [u8; 32],
    ) -> Result<BlockInfoTxs, AlloyChainProviderError> {
        Err(AlloyChainProviderError::BlockNotFound([0u8; 32]))
    }
}

pub struct BlobSource { pub chain_provider: ChainProvider }

impl BlobSource {
    /// BUG: collapses every error to Temporary via Backend wrap.
    pub fn load_blobs(&self, block_ref: BlockRef) -> Result<(), PipelineErrorKind> {
        let info = self
            .chain_provider
            .block_info_and_transactions_by_hash(block_ref.hash)
            .map_err(|e| PipelineErrorKind::Temporary(BlobProviderError::Backend(e.to_string())))?;
        let _ = info;
        Ok(())
    }
}
