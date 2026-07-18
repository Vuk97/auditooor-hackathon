// positive.rs — SHOULD fire: async RPC handler calls .expect() on block-field parse result

use jsonrpc_core::Error;

pub trait RpcServer {
    async fn get_block_header(
        &self,
        hash_or_height: String,
        verbose: Option<bool>,
    ) -> Result<String, Error>;
}

pub struct RpcImpl {
    network: Network,
}

pub struct Network;
pub struct Header {
    pub version: u32,
}

impl Header {
    // Returns Result<Commitment, CommitmentError> — can fail
    pub fn commitment(&self, network: &Network, height: u32) -> Result<Vec<u8>, String> {
        if height == 0 {
            return Err("unsupported height".to_string());
        }
        Ok(vec![0u8; 32])
    }
    pub fn coinbase_height(&self) -> Option<u32> {
        None
    }
}

impl RpcServer for RpcImpl {
    // VULNERABLE: async RPC handler calls .expect() on header.commitment()
    async fn get_block_header(
        &self,
        hash_or_height: String,
        verbose: Option<bool>,
    ) -> Result<String, Error> {
        let height: u32 = hash_or_height.parse().unwrap_or(0);
        let header = Header { version: 1 };

        // This .expect() panics if commitment() returns Err for any valid RPC input
        let block_commitments = header
            .commitment(&self.network, height)
            .expect("Unexpected failure while parsing the blockcommitments field in get_block_header");

        Ok(format!("{:?}", block_commitments))
    }
}
