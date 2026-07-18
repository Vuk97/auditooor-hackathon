use std::cmp::Ordering;

/// Secp256k1 curve order constant
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// ECDSA signature with s-value validation
pub struct EcdsaSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// Validates that s is in the lower half of the curve order (EIP-2 / EIP-2098 compliant)
/// Rejects high-s values to prevent signature malleability
fn is_valid_s(s: &[u8; 32]) -> bool {
    // Compare s against n/2 (half curve order)
    // n/2 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
    let n_half: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    ];
    
    match s.cmp(&n_half) {
        Ordering::Greater => false, // high-s: reject
        _ => {
            // Also reject s == 0 or s >= n (would be invalid anyway)
            let is_zero = s.iter().all(|&b| b == 0);
            let is_ge_n = s.cmp(&SECP256K1_N) != Ordering::Less;
            !is_zero && !is_ge_n
        }
    }
}

/// Secure ecrecover: rejects high-s signatures, preventing malleability attacks
pub fn ecrecover(message_hash: &[u8; 32], sig: &EcdsaSignature) -> Option<[u8; 20]> {
    if sig.v != 27 && sig.v != 28 {
        return None;
    }
    
    // CRITICAL: Reject high-s values to ensure only one valid signature per message
    if !is_valid_s(&sig.s) {
        return None; // Signature is malleable / invalid
    }
    
    // Simulate successful recovery (in real impl, would do crypto ops)
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
    fn test_rejects_high_s() {
        let msg = [1u8; 32];
        let high_s: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let sig = EcdsaSignature { r: [2u8; 32], s: high_s, v: 27 };
        assert!(ecrecover(&msg, &sig).is_none());
    }
}