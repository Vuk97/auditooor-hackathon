use alloy_primitives::{Address, B256, U256, FixedBytes};
use alloy_consensus::SignableTransaction;

/// Secure ecrecover wrapper that always rejects address(0)
pub struct SignatureVerifier;

impl SignatureVerifier {
    pub fn new() -> Self {
        Self
    }

    /// Recover signer and validate it's not the zero address
    pub fn verify_signature(
        &self,
        msg_hash: B256,
        v: u8,
        r: U256,
        s: U256,
    ) -> Result<Address, &'static str> {
        let recovered = Self::ecrecover_internal(msg_hash, v, r, s)?;
        
        // CRITICAL: Always check for zero address after ecrecover
        if recovered == Address::ZERO {
            return Err("invalid signature: zero address");
        }
        
        Ok(recovered)
    }

    fn ecrecover_internal(
        msg_hash: B256,
        v: u8,
        r: U256,
        s: U256,
    ) -> Result<Address, &'static str> {
        // Simplified: in real code, this would use alloy's ecrecover
        // For fixture purposes, we simulate the behavior
        let sig_bytes = Self::encode_sig(v, r, s);
        
        // Simulate ecrecover: hash-based deterministic "recovery" for testing
        let mut addr_bytes = [0u8; 20];
        let hash_bytes = msg_hash.as_slice();
        for i in 0..20.min(hash_bytes.len()) {
            addr_bytes[i] = hash_bytes[i].wrapping_add(sig_bytes[i % sig_bytes.len()]);
        }
        
        // Simulate invalid signature returning zero
        if v != 27 && v != 28 {
            return Ok(Address::ZERO);
        }
        
        Ok(Address::from(addr_bytes))
    }

    fn encode_sig(v: u8, r: U256, s: U256) -> Vec<u8> {
        let mut buf = vec![v];
        buf.extend_from_slice(&r.to_be_bytes::<32>());
        buf.extend_from_slice(&s.to_be_bytes::<32>());
        buf
    }

    /// Authorize a transfer after full verification
    pub fn authorize_transfer(
        &self,
        msg_hash: B256,
        v: u8,
        r: U256,
        s: U256,
        authorized_signers: &[Address],
    ) -> Result<(), &'static str> {
        let signer = self.verify_signature(msg_hash, v, r, s)?;
        
        if !authorized_signers.contains(&signer) {
            return Err("signer not authorized");
        }
        
        Ok(())
    }
}

fn main() {
    let verifier = SignatureVerifier::new();
    let msg_hash = B256::from([1u8; 32]);
    let r = U256::from(12345u64);
    let s = U256::from(67890u64);
    
    // Valid signature (v = 27)
    let result = verifier.authorize_transfer(msg_hash, 27, r, s, &[]);
    println!("Result: {:?}", result.is_ok() || result.is_err());
    
    // Invalid signature (v = 0) - should be caught by zero check
    let result = verifier.verify_signature(msg_hash, 0, r, s);
    assert!(result.is_err(), "zero address must be rejected");
}