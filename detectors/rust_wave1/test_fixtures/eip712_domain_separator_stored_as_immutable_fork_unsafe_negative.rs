use std::sync::atomic::{AtomicU64, Ordering};
use alloy_primitives::{keccak256, B256, U256};

/// Safe: DOMAIN_SEPARATOR recomputed on each use with current chain_id
pub struct SafeEip712Domain {
    name: String,
    version: String,
    verifying_contract: [u8; 20],
    salt: B256,
}

impl SafeEip712Domain {
    pub fn new(name: &str, version: &str, verifying_contract: [u8; 20], salt: B256) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            verifying_contract,
            salt,
        }
    }

    /// Get current chain_id - in real usage this would query the chain
    fn get_chain_id() -> u64 {
        // Simulated: in production, this calls chain_id() from the runtime
        1
    }

    /// Recompute DOMAIN_SEPARATOR with current chain_id on every call
    pub fn domain_separator(&self) -> B256 {
        let chain_id = Self::get_chain_id();
        let type_hash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
        );
        
        let name_hash = keccak256(self.name.as_bytes());
        let version_hash = keccak256(self.version.as_bytes());
        
        let mut encoded = Vec::with_capacity(160);
        encoded.extend_from_slice(&type_hash.0);
        encoded.extend_from_slice(&name_hash.0);
        encoded.extend_from_slice(&version_hash.0);
        encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
        encoded.extend_from_slice(&self.verifying_contract);
        encoded.extend_from_slice(&self.salt.0);
        
        keccak256(&encoded)
    }

    pub fn hash_typed_data(&self, struct_hash: B256) -> B256 {
        let prefix = b"\x19\x01";
        let mut full = Vec::with_capacity(66);
        full.extend_from_slice(prefix);
        full.extend_from_slice(&self.domain_separator().0);
        full.extend_from_slice(&struct_hash.0);
        keccak256(&full)
    }
}

fn main() {
    let domain = SafeEip712Domain::new(
        "MyApp",
        "1",
        [0u8; 20],
        B256::ZERO,
    );
    let _sep = domain.domain_separator();
    println!("Domain separator recomputed safely");
}