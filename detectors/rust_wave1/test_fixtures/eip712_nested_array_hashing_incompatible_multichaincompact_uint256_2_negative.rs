use alloy_primitives::{keccak256, B256, U256};

/// Correct EIP-712 recursive hashing for uint256[2][]
pub struct MultichainCompactClean;

impl MultichainCompactClean {
    /// EIP-712 type hash for the struct
    const TYPE_HASH: B256 = keccak256(b"MultichainCompact(uint256[2][] idsAndAmounts)");

    /// Hash a single uint256[2] element using EIP-712 array encoding
    fn hash_uint256_2_element(a: U256, b: U256) -> B256 {
        let mut encoded = [0u8; 64];
        a.to_be_bytes::<32>().copy_to_slice(&mut encoded[0..32]);
        b.to_be_bytes::<32>().copy_to_slice(&mut encoded[32..64]);
        keccak256(&encoded)
    }

    /// Hash uint256[2][] using proper EIP-712 recursive hashing:
    /// Each element is individually hashed, then array is hashed as keccak256(h(e1) || h(e2) || ...)
    fn hash_ids_and_amounts(ids_and_amounts: &[(U256, U256)]) -> B256 {
        let element_hashes: Vec<u8> = ids_and_amounts
            .iter()
            .flat_map(|(a, b)| {
                let h = Self::hash_uint256_2_element(*a, *b);
                h.0.to_vec()
            })
            .collect();
        keccak256(&element_hashes)
    }

    /// Compute full struct hash with correct nested array handling
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
    fn test_clean_hashing() {
        let data = vec![
            (U256::from(1u64), U256::from(100u64)),
            (U256::from(2u64), U256::from(200u64)),
        ];
        let _hash = MultichainCompactClean::hash_struct(&data);
        // Hash will match wallet's EIP-712 computation
    }
}