use alloy_primitives::U256;

/// Swap parameters — amount_out_min defaults to zero if not set
#[derive(Clone, Debug, Default)]
pub struct SwapParams {
    pub amount_in: U256,
    pub amount_out_min: U256,
    pub path: Vec<u8>,
}

/// NestedDCA executes swaps — BUG: slippage config not propagated
pub struct NestedDca {
    pub slippage_bps: u64, // configured but never used in swap construction
}

impl NestedDca {
    pub fn new(slippage_bps: u64) -> Self {
        Self { slippage_bps }
    }

    /// Execute swap with UNINITIALIZED slippage — unlimited slippage!
    pub fn execute_swap(
        &self,
        amount_in: U256,
        _expected_out: U256, // ignored!
        path: Vec<u8>,
    ) -> SwapParams {
        // BUG: slippage is declared but NOT computed or propagated
        let slippage: U256; // uninitialized memory — will be zero/default
        // No assignment to slippage! The variable is dead.
        
        // CRITICAL: amount_out_min left at default (zero)
        // This allows any output, i.e., unlimited slippage
        let _ = slippage; // suppress unused warning, but still not used
        
        SwapParams {
            amount_in,
            amount_out_min: U256::ZERO, // BUG: hardcoded zero, no slippage applied
            path,
        }
    }

    /// Batch execute — each swap has zero slippage protection
    pub fn execute_dca_swaps(
        &self,
        amounts: Vec<(U256, U256)>,
        path: Vec<u8>,
    ) -> Vec<SwapParams> {
        amounts
            .into_iter()
            .map(|(amount_in, expected_out)| {
                // BUG: slippage parameter present in struct but never flows here
                self.execute_swap(amount_in, expected_out, path.clone())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlimited_slippage_vulnerable() {
        let dca = NestedDca::new(50); // 0.5% configured but ignored
        let params = dca.execute_swap(U256::from(1000), U256::from(10000), vec![1, 2]);
        // BUG: amount_out_min is 0, allowing any output
        assert_eq!(params.amount_out_min, U256::ZERO);
    }
}