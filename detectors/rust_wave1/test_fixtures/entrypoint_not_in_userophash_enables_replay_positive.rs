use alloy_primitives::{Address, B256, U256, FixedBytes};
use alloy_consensus::TypedTransaction;
use std::collections::HashMap;

/// UserOperation for ERC-4337 account abstraction
#[derive(Debug, Clone)]
pub struct UserOperation {
    pub sender: Address,
    pub nonce: U256,
    pub init_code: Vec<u8>,
    pub call_data: Vec<u8>,
    pub call_gas_limit: U256,
    pub verification_gas_limit: U256,
    pub pre_verification_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub paymaster_and_data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// BUG: EntryPoint NOT included in hash — enables replay across EntryPoint deployments
pub struct UserOpHasher {
    pub chain_id: u64,
    // entry_point stored but NEVER used in hashing
    pub entry_point: Address,
}

impl UserOpHasher {
    pub fn new(chain_id: u64, entry_point: Address) -> Self {
        Self { chain_id, entry_point }
    }

    /// VULNERABLE: Compute userOpHash WITHOUT entryPoint address
    /// This allows replay attacks: same userOp valid on any EntryPoint on same chain
    pub fn hash_user_op(&self, user_op: &UserOperation) -> B256 {
        // Pack: sender, nonce, hash(initCode), hash(callData), callGasLimit,
        // verificationGasLimit, preVerificationGas, maxFeePerGas,
        // maxPriorityFeePerGas, hash(paymasterAndData), chainId
        // MISSING: entryPoint
        let mut hasher = alloy_primitives::Keccak256::new();
        
        hasher.update(user_op.sender.as_slice());
        hasher.update(&user_op.nonce.to_be_bytes::<32>());
        hasher.update(alloy_primitives::keccak256(&user_op.init_code).as_slice());
        hasher.update(alloy_primitives::keccak256(&user_op.call_data).as_slice());
        hasher.update(&user_op.call_gas_limit.to_be_bytes::<32>());
        hasher.update(&user_op.verification_gas_limit.to_be_bytes::<32>());
        hasher.update(&user_op.pre_verification_gas.to_be_bytes::<32>());
        hasher.update(&user_op.max_fee_per_gas.to_be_bytes::<32>());
        hasher.update(&user_op.max_priority_fee_per_gas.to_be_bytes::<32>());
        hasher.update(alloy_primitives::keccak256(&user_op.paymaster_and_data).as_slice());
        // Only chainId included — entryPoint deliberately omitted (BUG)
        hasher.update(&self.chain_id.to_be_bytes());
        // self.entry_point.as_slice() is NOT called here — the vulnerability
        
        hasher.finalize()
    }

    /// Verify signature — also vulnerable, uses same broken hash
    pub fn verify_signature(&self, user_op: &UserOperation, expected_hash: B256) -> bool {
        let computed = self.hash_user_op(user_op);
        computed == expected_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_vulnerable_to_replay() {
        let ep1 = Address::from([0x11u8; 20]);
        let ep2 = Address::from([0x22u8; 20]);
        let hasher1 = UserOpHasher::new(1, ep1);
        let hasher2 = UserOpHasher::new(1, ep2);
        
        let user_op = UserOperation {
            sender: Address::from([0x33u8; 20]),
            nonce: U256::from(0),
            init_code: vec![],
            call_data: vec![0x12, 0x34],
            call_gas_limit: U256::from(100000),
            verification_gas_limit: U256::from(100000),
            pre_verification_gas: U256::from(21000),
            max_fee_per_gas: U256::from(1),
            max_priority_fee_per_gas: U256::from(1),
            paymaster_and_data: vec![],
            signature: vec![],
        };
        
        let hash1 = hasher1.hash_user_op(&user_op);
        let hash2 = hasher2.hash_user_op(&user_op);
        
        // BUG: Same hash despite different entryPoints — replay possible!
        assert_eq!(hash1, hash2, "BUG: EntryPoint does not affect hash — replayable!");
    }
}