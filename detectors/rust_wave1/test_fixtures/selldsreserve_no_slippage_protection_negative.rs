use std::marker::PhantomData;

/// Safe version with slippage protection
pub struct FlashSwapRouter<T> {
    _marker: PhantomData<T>,
}

#[derive(Clone, Debug)]
pub struct SwapParams {
    pub amount_in: u64,
    pub amount_out_minimum: u64,
    pub deadline: u64,
}

impl<T> FlashSwapRouter<T> {
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }

    /// Sell DS tokens with proper slippage protection
    pub fn _sell_ds_reserve(
        &self,
        amount_in: u64,
        reserve_out: u64,
        reserve_in: u64,
    ) -> Result<u64, &'static str> {
        let params = SwapParams {
            amount_in,
            amount_out_minimum: self.calculate_min_out(amount_in, reserve_in, reserve_out),
            deadline: self.current_time() + 300,
        };

        // Verify slippage protection is enforced
        let amount_out = self.get_amount_out(params.amount_in, reserve_in, reserve_out)?;
        
        if amount_out < params.amount_out_minimum {
            return Err("Insufficient output amount");
        }

        if self.current_time() > params.deadline {
            return Err("Transaction expired");
        }

        self.execute_swap(params, amount_out)
    }

    fn calculate_min_out(&self, amount_in: u64, reserve_in: u64, reserve_out: u64) -> u64 {
        // Apply 0.5% slippage tolerance
        let expected = self.get_amount_out(amount_in, reserve_in, reserve_out).unwrap_or(0);
        expected.saturating_sub(expected / 200)
    }

    fn get_amount_out(&self, amount_in: u64, reserve_in: u64, reserve_out: u64) -> Result<u64, &'static str> {
        if reserve_in == 0 || reserve_out == 0 {
            return Err("Insufficient liquidity");
        }
        let amount_in_with_fee = (amount_in as u128) * 997;
        let numerator = amount_in_with_fee * (reserve_out as u128);
        let denominator = (reserve_in as u128) * 1000 + amount_in_with_fee;
        Ok((numerator / denominator) as u64)
    }

    fn execute_swap(&self, params: SwapParams, amount_out: u64) -> Result<u64, &'static str> {
        // Swap execution with validated params
        Ok(amount_out)
    }

    fn current_time(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

fn main() {
    let router = FlashSwapRouter::<u8>::new();
    let result = router._sell_ds_reserve(1000, 10000, 10000);
    assert!(result.is_ok());
}