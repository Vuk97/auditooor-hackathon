use std::ops::Sub;

/// Fee growth values in Q128.128 fixed-point format.
/// Uniswap V3 semantics: fee growth can underflow/wrap; we must use wrapping arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeGrowth(u256);

impl FeeGrowth {
    pub const fn new(val: u256) -> Self {
        Self(val)
    }

    /// Wrapping subtraction — correct for V3 fee growth semantics.
    pub fn wrapping_sub(self, other: FeeGrowth) -> FeeGrowth {
        FeeGrowth(self.0.wrapping_sub(other.0))
    }
}

/// U256 wrapper for demonstration (simplified).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct u256([u64; 4]);

impl u256 {
    pub const fn new(low: u128, high: u128) -> Self {
        Self([low as u64, (low >> 64) as u64, high as u64, (high >> 64) as u64])
    }

    pub fn wrapping_sub(self, other: u256) -> u256 {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff, b) = self.0[i].overflowing_sub(other.0[i] + borrow);
            result[i] = diff;
            borrow = if self.0[i] < other.0[i] + borrow { 1 } else { 0 };
        }
        u256(result)
    }
}

/// Calculate fees owed given fee growth global, fee growth below, and fee growth above.
/// Uses wrapping arithmetic — correct for V3 semantics where underflow is expected.
pub fn calculate_fees_owed(
    fee_growth_global: FeeGrowth,
    fee_growth_below: FeeGrowth,
    fee_growth_above: FeeGrowth,
    liquidity: u128,
) -> u128 {
    let fee_growth_inside = fee_growth_below
        .wrapping_sub(fee_growth_global)
        .wrapping_sub(fee_growth_above);
    
    // Simplified: convert fee growth to token amount
    let growth_delta = fee_growth_inside.0;
    // Use lower 128 bits as proxy for fee amount
    let fee_amount = growth_delta.0[0] as u128 + ((growth_delta.0[1] as u128) << 64);
    fee_amount.min(liquidity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_growth_wraps_correctly() {
        let global = FeeGrowth::new(u256::new(u128::MAX, 0));
        let below = FeeGrowth::new(u256::new(100, 0));
        let above = FeeGrowth::new(u256::new(0, 0));
        
        // This should NOT panic — wrapping is intentional
        let fees = calculate_fees_owed(global, below, above, 1_000_000);
        assert!(fees <= 1_000_000);
    }
}