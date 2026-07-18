use std::marker::PhantomData;

/// Vulnerable version missing slippage protection
pub struct FlashSwapRouter<T> {
    _marker: PhantomData<T>,
}

#[derive(Clone, Debug)]
pub struct SwapParams {
    pub amount_in: u64,
    // NOTE: No amount_out_minimum field
    pub deadline: u64,
}

impl<T> FlashSwapRouter<T> {
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }

    /// Sell DS tokens WITHOUT slippage protection - vulnerable to MEV
    pub fn _sell_ds_reserve(
        &self,
        amount_in: u64,
        reserve_out: u64,
        reserve_in: u64,
    ) -> Result<u64, &'static str> {
        let params = SwapParams {
            amount_in,
            // BUG: No amount_out_minimum specified - accepts any output
            deadline: self.current_time() + 300,
        };

        // Direct swap without minimum output check
        let amount_out = self.get_amount_out(params.amount_in, reserve_in, reserve_out)?;
        
        // Only check deadline, no slippage protection
        if self.current_time() > params.deadline {
            return Err("Transaction expired");
        }

        self.execute_swap(params, amount_out)
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

    fn execute_swap(&self, _params: SwapParams, amount_out: u64) -> Result<u64, &'static str> {
        // Swap execution without any minimum output validation
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