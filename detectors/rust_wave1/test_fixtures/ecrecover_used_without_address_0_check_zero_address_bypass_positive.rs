use alloy_primitives::{Address, B256, U256};

/// INSECURE: ecrecover wrapper with NO zero address check
/// This allows bypass with invalid signatures that return address(0)
pub struct SignatureVerifier;

impl SignatureVerifier {
    pub fn new() -> Self {
        Self
    }

    /// VULNERABLE: Recover signer WITHOUT validating it's not zero address
    /// ecrecover returns address(0) for invalid signatures - this is NOT checked
    pub fn recover_signer(
        &self,
        msg_hash: B256,
        v: u8,
        r: U256,
        s: U256,
    ) -> Result<Address, &'static str> {
        let recovered = Self::ecrecover_internal(msg_hash, v, r, s)?;
        
        // BUG: Missing check: if recovered == Address::ZERO { return Err(...); }
        // This allows any invalid signature to "authenticate" as address(0)
        
        Ok(recovered)
    }

    fn ecrecover_internal(
        msg_hash: B256,
        v: u8,
        r: U256,
        s: U256,
    ) -> Result<Address, &'static str> {
        // Simplified simulation of ecrecover behavior
        let sig_bytes = Self::encode_sig(v, r, s);
        
        let mut addr_bytes = [0u8; 20];
        let hash_bytes = msg_hash.as_slice();
        for i in 0..20.min(hash_bytes.len()) {
            addr_bytes[i] = hash_bytes[i].wrapping_add(sig_bytes[i % sig_bytes.len()]);
        }
        
        // ecrecover returns zero for invalid signatures (bad v value)
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

    /// VULNERABLE: Authorize using recovered signer without zero check
    /// If authorized_signers contains or defaults to address(0), attacker wins
    pub fn authorize_transfer(
        &self,
        msg_hash: B256,
        v: u8,
        r: U256,
        s: U256,
        authorized_signers: &[Address],
    ) -> Result<(), &'static str> {
        // BUG: recover_signer does NOT check for zero address
        let signer = self.recover_signer(msg_hash, v, r, s)?;
        
        // If authorized_signers is empty or contains ZERO, attacker passes
        // zero signature (v=0, r=0, s=0) and gets address(0) "authenticated"
        if !authorized_signers.contains(&signer) {
            return Err("signer not authorized");
        }
        
        Ok(())
    }
    
    /// Even worse: direct ecrecover usage in authorization with no check at all
    pub fn dangerous_authorize(
        &self,
        msg_hash: B256,
        v: u8,
        r: U256,
        s: U256,
        expected_signer: Address,
    ) -> bool {
        // Direct ecrecover result used without zero check
        let recovered = Self::ecrecover_internal(msg_hash, v, r, s).unwrap_or(Address::ZERO);
        
        // If expected_signer is ZERO or we got ZERO from bad sig, this may pass
        recovered == expected_signer
    }
}

fn main() {
    let verifier = SignatureVerifier::new();
    let msg_hash = B256::from([1u8; 32]);
    let zero_r = U256::ZERO;
    let zero_s = U256::ZERO;
    
    // Attacker sends invalid signature with v=0 - ecrecover returns address(0)
    // If contract has address(0) as default authorized, this bypasses security
    let recovered = verifier.recover_signer(msg_hash, 0, zero_r, zero_s);
    println!("Attacker recovered (should be ZERO): {:?}", recovered.is_ok());
    
    // Demonstrate bypass: attacker can "authenticate" as zero address
    let authorized = vec![Address::ZERO]; // Lazy init or default state
    let bypass = verifier.authorize_transfer(msg_hash, 0, zero_r, zero_s, &authorized);
    println!("Bypass succeeded: {:?}", bypass.is_ok());
}