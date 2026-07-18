use alloy_primitives::{Address, B256, FixedBytes};

pub struct SignatureVerifier {
    owner: Address,
}

impl SignatureVerifier {
    pub fn new(owner: Address) -> Self {
        Self { owner }
    }

    /// ECDSA.recover returns address(0) for malformed signatures.
    /// We MUST reject address(0) to prevent signature forgery.
    pub fn _validate_signature(
        &self,
        hash: B256,
        signature: &[u8; 65],
    ) -> Result<(), &'static str> {
        let recovered = Self::ecdsa_recover(hash, signature)?;
        
        // CRITICAL FIX: explicitly reject address(0)
        if recovered == Address::ZERO {
            return Err("invalid signature: recovered address is zero");
        }
        
        if recovered != self.owner {
            return Err("signature does not match owner");
        }
        
        Ok(())
    }

    fn ecdsa_recover(hash: B256, signature: &[u8; 65]) -> Result<Address, &'static str> {
        // Simplified: in real code this calls secp256k1 recovery
        // Returns address(0) on failure/malformed sig
        if signature[64] > 1 {
            return Err("invalid recovery id");
        }
        // Mock recovery for demonstration
        let addr_bytes: [u8; 20] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67,
        ];
        Ok(Address::from_slice(&addr_bytes))
    }
}

fn main() {
    let verifier = SignatureVerifier::new(Address::from([0x42u8; 20]));
    let hash = B256::from([0u8; 32]);
    let sig = [0u8; 65];
    
    // This will fail with invalid signature due to our zero check
    let _ = verifier._validate_signature(hash, &sig);
}