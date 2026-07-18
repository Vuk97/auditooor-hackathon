use alloy_primitives::U256;

/// Swap parameters with explicit slippage propagation
#[derive(Clone, Debug)]
pub struct SwapParams {
    pub amount_in: U256,
    pub amount_out_min: U256,
    pub path: Vec<u8>,
}

/// NestedDCA executes swaps with proper slippage enforcement
pub struct NestedDca {
    pub slippage_bps: u64, // basis points, e.g. 50 = 0.5%
}

impl NestedDca {
    pub fn new(slippage_bps: u64) -> Self {
        Self { slippage_bps }
    }

    /// Calculate minimum output with slippage applied
    fn apply_slippage(&self, expected_out: U256) -> U256 {
        let slippage_factor = U256::from(10000 - self.slippage_bps);
        expected_out * slippage_factor / U256::from(10000)
    }

    /// Execute swap with propagated slippage guard
    pub fn execute_swap(
        &self,
        amount_in: U256,
        expected_out: U256,
        path: Vec<u8>,
    ) -> SwapParams {
        // CRITICAL: slippage is computed and propagated
        let amount_out_min = self.apply_slippage(expected_out);
        
        SwapParams {
            amount_in,
            amount_out_min, // properly derived from slippage config
            path,
        }
    }

    /// Batch execute multiple swaps, each with slippage applied
    pub fn execute_dca_swaps(
        &self,
        amounts: Vec<(U256, U256)>, // (amount_in, expected_out)
        path: Vec<u8>,
    ) -> Vec<SwapParams> {
        amounts
            .into_iter()
            .map(|(amount_in, expected_out)| {
                self.execute_swap(amount_in, expected_out, path.clone())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slippage_applied() {
        let dca = NestedDca::new(50); // 0.5% slippage
        let expected = U256::from(10000);
        let params = dca.execute_swap(U256::from(1000), expected, vec![1, 2]);
        assert_eq!(params.amount_out_min, U256::from(9950));
    }
}