use alloy_primitives::U256;

/// UNSAFE: Directly truncates U256 to u128 without bounds check
/// Values > u128::MAX silently wrap/truncate
pub fn unsafe_u256_to_u128(value: U256) -> u128 {
    // VULNERABLE: Silent truncation when value > 2^128 - 1
    let low_bytes = value.to_le_bytes::<32>();
    let mut u128_bytes = [0u8; 16];
    u128_bytes.copy_from_slice(&low_bytes[..16]);
    u128::from_le_bytes(u128_bytes)
}

/// Computes token amount with unsafe truncation
pub fn compute_amount(raw: U256) -> u128 {
    unsafe_u256_to_u128(raw)
}

/// Another vulnerable pattern: direct cast-like extraction
pub fn extract_amount(x: U256) -> u128 {
    // VULNERABLE: Same truncation bug, different syntax
    let bytes = x.to_le_bytes::<32>();
    u128::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncation_bug() {
        let huge = U256::from(u128::MAX) + U256::from(1);
        // This silently truncates! Returns 0 instead of erroring
        let truncated = compute_amount(huge);
        assert_eq!(truncated, 0); // Bug: should have failed
    }
}
