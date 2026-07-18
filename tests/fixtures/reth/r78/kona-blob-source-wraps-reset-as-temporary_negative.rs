// Post-fix shape: chain-provider BlockNotFound maps to Reset, not Temporary.

#![allow(dead_code, unused_variables)]

#[derive(Debug)]
pub enum AlloyChainProviderError {
    BlockNotFound([u8; 32]),
    Other,
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
    pub fn load_blobs(&self, block_ref: BlockRef) -> Result<(), PipelineErrorKind> {
        let info = self
            .chain_provider
            .block_info_and_transactions_by_hash(block_ref.hash)
            .map_err(|e| match e {
                AlloyChainProviderError::BlockNotFound(_) => PipelineErrorKind::Reset,
                AlloyChainProviderError::Other => {
                    PipelineErrorKind::Temporary(BlobProviderError::Backend("backend".into()))
                }
            })?;
        let _ = info;
        Ok(())
    }
}
