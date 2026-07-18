use alloy_primitives::{keccak256, B256, U256};

/// INCORRECT: Flat concatenation hashing for uint256[2][]
/// This violates EIP-712 which requires recursive hashing of array elements
pub struct MultichainCompactVulnerable;

impl MultichainCompactVulnerable {
    /// EIP-712 type hash for the struct
    const TYPE_HASH: B256 = keccak256(b"MultichainCompact(uint256[2][] idsAndAmounts)");

    /// BUG: Incorrectly hashes uint256[2][] by flat concatenation of inner arrays
    /// instead of hashing each element individually first.
    /// This produces a different hash than wallets computing proper EIP-712.
    fn hash_ids_and_amounts(ids_and_amounts: &[(U256, U256)]) -> B256 {
        // VULNERABLE: Direct concatenation of all uint256 values without
        // per-element hashing. This is NOT EIP-712 compliant.
        let mut flat_encoded = Vec::new();
        for (a, b) in ids_and_amounts {
            let mut buf = [0u8; 64];
            a.to_be_bytes::<32>().copy_to_slice(&mut buf[0..32]);
            b.to_be_bytes::<32>().copy_to_slice(&mut buf[32..64]);
            flat_encoded.extend_from_slice(&buf);
        }
        keccak256(&flat_encoded)
    }

    /// Compute struct hash with INCORRECT nested array handling
    pub fn hash_struct(ids_and_amounts: &[(U256, U256)]) -> B256 {
        let type_hash = Self::TYPE_HASH;
        let array_hash = Self::hash_ids_and_amounts(ids_and_amounts);
        
        let mut encoded = Vec::with_capacity(64);
        encoded.extend_from_slice(&type_hash.0);
        encoded.extend_from_slice(&array_hash.0);
        keccak256(&encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_hashing() {
        let data = vec![
            (U256::from(1u64), U256::from(100u64)),
            (U256::from(2u64), U256::from(200u64)),
        ];
        let _hash = MultichainCompactVulnerable::hash_struct(&data);
        // Hash will NOT match wallet's EIP-712 computation - signatures fail!
    }
}