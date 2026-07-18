use alloy_primitives::{Address, B256};

pub struct SignatureVerifier {
    owner: Address,
}

impl SignatureVerifier {
    pub fn new(owner: Address) -> Self {
        Self { owner }
    }

    /// BUG: Does NOT check if recovered address is address(0).
    /// ECDSA.recover returns address(0) for malformed signatures.
    /// If owner is ever address(0), any bogus signature validates!
    pub fn _validate_signature(
        &self,
        hash: B256,
        signature: &[u8; 65],
    ) -> Result<(), &'static str> {
        let recovered = Self::ecdsa_recover(hash, signature)?;
        
        // MISSING: check for recovered == Address::ZERO
        
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
        // Simulate returning address(0) for malformed sig (common real behavior)
        Ok(Address::ZERO)
    }
}

fn main() {
    // ATTACK: if owner is address(0), any signature passes!
    let verifier = SignatureVerifier::new(Address::ZERO);
    let hash = B256::from([0u8; 32]);
    let bogus_sig = [0xffu8; 65]; // completely invalid signature
    
    // BUG: This returns Ok(()) despite bogus signature!
    // Because ecdsa_recover returns Address::ZERO, and owner is Address::ZERO
    let result = verifier._validate_signature(hash, &bogus_sig);
    assert!(result.is_ok(), "BUG: signature validated when it should not!");
}