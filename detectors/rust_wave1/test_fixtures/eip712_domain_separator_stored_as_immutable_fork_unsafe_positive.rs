use alloy_primitives::{keccak256, B256, U256};

/// VULNERABLE: DOMAIN_SEPARATOR cached as immutable at construction time
/// After a hardfork/chainId change, signatures become replayable across chains
pub struct VulnerableEip712Domain {
    name: String,
    version: String,
    verifying_contract: [u8; 20],
    salt: B256,
    /// CACHED at construction - does NOT reflect chainId changes after forks
    domain_separator: B256,
}

impl VulnerableEip712Domain {
    pub fn new(name: &str, version: &str, verifying_contract: [u8; 20], salt: B256) -> Self {
        let chain_id = Self::get_chain_id_at_construction();
        
        // BUG: This is computed ONCE at construction and never updated
        let domain_separator = Self::compute_domain_separator(
            name,
            version,
            chain_id,
            verifying_contract,
            salt,
        );
        
        Self {
            name: name.to_string(),
            version: version.to_string(),
            verifying_contract,
            salt,
            domain_separator, // IMMUTABLE cache - fork-unsafe!
        }
    }

    fn get_chain_id_at_construction() -> u64 {
        // Simulated: captures chain_id at deployment time
        1
    }

    fn compute_domain_separator(
        name: &str,
        version: &str,
        chain_id: u64,
        verifying_contract: [u8; 20],
        salt: B256,
    ) -> B256 {
        let type_hash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
        );
        
        let name_hash = keccak256(name.as_bytes());
        let version_hash = keccak256(version.as_bytes());
        
        let mut encoded = Vec::with_capacity(160);
        encoded.extend_from_slice(&type_hash.0);
        encoded.extend_from_slice(&name_hash.0);
        encoded.extend_from_slice(&version_hash.0);
        encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
        encoded.extend_from_slice(&verifying_contract);
        encoded.extend_from_slice(&salt.0);
        
        keccak256(&encoded)
    }

    /// Returns the CACHED domain separator - vulnerable after fork!
    pub fn domain_separator(&self) -> B256 {
        self.domain_separator // Returns stale value after chainId change
    }

    pub fn hash_typed_data(&self, struct_hash: B256) -> B256 {
        let prefix = b"\x19\x01";
        let mut full = Vec::with_capacity(66);
        full.extend_from_slice(prefix);
        full.extend_from_slice(&self.domain_separator.0); // Uses stale cache!
        full.extend_from_slice(&struct_hash.0);
        keccak256(&full)
    }
}

fn main() {
    let domain = VulnerableEip712Domain::new(
        "MyApp",
        "1",
        [0u8; 20],
        B256::ZERO,
    );
    let _sep = domain.domain_separator();
    println!("WARNING: Domain separator is cached and fork-unsafe!");
}