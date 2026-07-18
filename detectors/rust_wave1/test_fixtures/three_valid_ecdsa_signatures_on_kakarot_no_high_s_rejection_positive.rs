use std::cmp::Ordering;

/// Secp256k1 curve order constant
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// ECDSA signature WITHOUT s-value validation
pub struct EcdsaSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// BUG: No high-s rejection. Accepts any s value, enabling signature malleability.
/// This allows 3 valid signatures for same message: (r,s,v), (r,n-s,v^1), EIP-2098 compact.
fn is_valid_s(_s: &[u8; 32]) -> bool {
    // VULNERABLE: Always returns true, never rejects high-s
    true
}

/// INSECURE ecrecover: accepts high-s signatures, allowing replay attacks
/// 
/// The Kakarot bug: ecrecover precompile returns valid address for high-s
/// instead of address(0). Same message produces multiple valid signatures.
pub fn ecrecover(message_hash: &[u8; 32], sig: &EcdsaSignature) -> Option<[u8; 20]> {
    if sig.v != 27 && sig.v != 28 {
        return None;
    }
    
    // BUG: Missing high-s check! Accepts malleable signatures.
    // Should reject when s > n/2, but doesn't.
    // This enables: original sig, high-s variant, and EIP-2098 compact form
    // all to verify as valid for the same message.
    
    // Only checks s != 0 and s < n (basic range, not malleability check)
    let is_zero = sig.s.iter().all(|&b| b == 0);
    let is_ge_n = sig.s.cmp(&SECP256K1_N) != Ordering::Less;
    if is_zero || is_ge_n {
        return None;
    }
    
    // Simulate recovery - returns address even for high-s (the bug)
    let mut addr = [0u8; 20];
    for i in 0..20 {
        addr[i] = sig.r[i] ^ sig.s[i] ^ message_hash[i];
    }
    Some(addr)
}

/// Alternative vulnerable pattern: completely missing s validation
pub fn ecrecover_no_s_check_at_all(message_hash: &[u8; 32], sig: &EcdsaSignature) -> Option<[u8; 20]> {
    if sig.v != 27 && sig.v != 28 {
        return None;
    }
    // NO s validation whatsoever - even more vulnerable
    let mut addr = [0u8; 20];
    for i in 0..20 {
        addr[i] = sig.r[i] ^ sig.s[i] ^ message_hash[i];
    }
    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_high_s_bug() {
        let msg = [1u8; 32];
        let high_s: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let sig = EcdsaSignature { r: [2u8; 32], s: high_s, v: 27 };
        // BUG: This returns Some(addr) instead of None
        assert!(ecrecover(&msg, &sig).is_some());
    }
}