use std::ops::Sub;

/// Fee growth values in Q128.128 fixed-point format.
/// DANGER: Using checked arithmetic that will panic on expected underflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeGrowth(u256);

impl FeeGrowth {
    pub const fn new(val: u256) -> Self {
        Self(val)
    }
}

/// U256 wrapper with checked arithmetic (simulating SafeMath behavior).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct u256([u64; 4]);

impl u256 {
    pub const fn new(low: u128, high: u128) -> Self {
        Self([low as u64, (low >> 64) as u64, high as u64, (high >> 64) as u64])
    }

    /// Checked subtraction — panics on underflow (simulating SafeMath).
    pub fn checked_sub(self, other: u256) -> Option<u256> {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff, b) = self.0[i].overflowing_sub(other.0[i] + borrow);
            result[i] = diff;
            borrow = if self.0[i] < other.0[i] + borrow { 1 } else { 0 };
        }
        if borrow != 0 {
            None
        } else {
            Some(u256(result))
        }
    }
}

impl Sub for FeeGrowth {
    type Output = Self;

    /// DANGER: This uses checked subtraction, which will panic when
    /// fee_growth_below > fee_growth_global — exactly what happens in V3!
    fn sub(self, other: FeeGrowth) -> Self::Output {
        let result = self.0.checked_sub(other.0)
            .expect("SafeMath: subtraction underflow");
        FeeGrowth(result)
    }
}

/// Calculate fees owed — BUG: uses checked arithmetic that reverts on expected underflow.
pub fn calculate_fees_owed(
    fee_growth_global: FeeGrowth,
    fee_growth_below: FeeGrowth,
    fee_growth_above: FeeGrowth,
    liquidity: u128,
) -> u128 {
    // BUG: fee_growth_below - fee_growth_global underflows when below > global!
    // In V3, fee growth values are monotonic per position but cross-tick ordering
    // means fee_growth_below can exceed fee_growth_global after ticks cross.
    let fee_growth_inside = fee_growth_below - fee_growth_global - fee_growth_above;
    
    // Simplified: convert fee growth to token amount
    let growth_delta = fee_growth_inside.0;
    let fee_amount = growth_delta.0[0] as u128 + ((growth_delta.0[1] as u128) << 64);
    fee_amount.min(liquidity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "SafeMath: subtraction underflow")]
    fn test_fee_growth_reverts_on_underflow() {
        let global = FeeGrowth::new(u256::new(u128::MAX, 0));
        let below = FeeGrowth::new(u256::new(100, 0)); // below > global in wrapped sense
        let above = FeeGrowth::new(u256::new(0, 0));
        
        // This WILL panic — bug! Should use wrapping arithmetic for V3 fee growth.
        let _fees = calculate_fees_owed(global, below, above, 1_000_000);
    }
}