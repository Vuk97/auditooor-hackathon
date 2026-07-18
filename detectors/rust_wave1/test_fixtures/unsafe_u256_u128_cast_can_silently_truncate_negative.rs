use alloy_primitives::U256;

/// Safely converts U256 to u128 with explicit overflow check
pub fn safe_u256_to_u128(value: U256) -> Option<u128> {
    if value > U256::from(u128::MAX) {
        None
    } else {
        // Safe: we've verified the value fits
        let bytes = value.to_le_bytes::<32>();
        let mut u128_bytes = [0u8; 16];
        u128_bytes.copy_from_slice(&bytes[..16]);
        Some(u128::from_le_bytes(u128_bytes))
    }
}

/// Computes token amount with safe conversion
pub fn compute_amount(raw: U256) -> Option<u128> {
    safe_u256_to_u128(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_conversion() {
        assert_eq!(compute_amount(U256::from(100u128)), Some(100));
        assert_eq!(compute_amount(U256::from(u128::MAX)), Some(u128::MAX));
        assert_eq!(compute_amount(U256::from(u128::MAX) + U256::from(1)), None);
    }
}
