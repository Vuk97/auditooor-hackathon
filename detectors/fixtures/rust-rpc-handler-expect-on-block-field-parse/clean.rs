// clean.rs — should NOT fire: async RPC handler properly propagates block-field parse errors

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

fn to_rpc_error(e: String) -> Error {
    Error::invalid_params(e)
}

impl Header {
    pub fn commitment(&self, network: &Network, height: u32) -> Result<Vec<u8>, String> {
        if height == 0 {
            return Err("unsupported height".to_string());
        }
        Ok(vec![0u8; 32])
    }
}

impl RpcServer for RpcImpl {
    // SAFE: uses ? / map_err to propagate commitment errors as JSON-RPC error responses
    async fn get_block_header(
        &self,
        hash_or_height: String,
        verbose: Option<bool>,
    ) -> Result<String, Error> {
        let height: u32 = hash_or_height.parse().unwrap_or(0);
        let header = Header { version: 1 };

        // Proper error propagation — no panic risk
        let block_commitments = header
            .commitment(&self.network, height)
            .map_err(to_rpc_error)?;

        Ok(format!("{:?}", block_commitments))
    }
}

// Non-async helper functions with .expect() are fine (not an RPC handler)
fn compute_commitment_sync(header: &Header, network: &Network, height: u32) -> Vec<u8> {
    header.commitment(network, height).expect("internal call site — height always valid")
}
