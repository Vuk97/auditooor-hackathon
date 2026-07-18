use std::collections::HashMap;

/// Clean version: DS reserve sale with proper slippage protection
pub struct FlashSwapRouter {
    reserves: HashMap<u64, u64>,
}

pub struct SellDsParams {
    pub ds_id: u64,
    pub amount_in: u64,
    pub amount_out_min: u64,  // Slippage protection present
    pub deadline: u64,
}

impl FlashSwapRouter {
    pub fn new() -> Self {
        Self {
            reserves: HashMap::new(),
        }
    }

    pub fn set_reserve(&mut self, id: u64, amount: u64) {
        self.reserves.insert(id, amount);
    }

    /// Sell DS tokens with minimum output check (clean)
    pub fn sell_ds_reserve(
        &mut self,
        params: &SellDsParams,
        current_time: u64,
    ) -> Result<u64, &'static str> {
        // Check deadline
        if current_time > params.deadline {
            return Err("Deadline exceeded");
        }

        // Calculate output based on reserve ratio
        let reserve = self.reserves.get(&params.ds_id).copied().unwrap_or(0);
        if reserve == 0 {
            return Err("No reserve found");
        }

        // Simplified AMM calculation
        let amount_out = self.calculate_output(params.amount_in, reserve);

        // CRITICAL: Enforce minimum output (slippage protection)
        if amount_out < params.amount_out_min {
            return Err("Slippage exceeded: amount_out < amount_out_min");
        }

        // Update reserve
        let new_reserve = reserve.checked_sub(amount_out).ok_or("Insufficient reserve")?;
        self.reserves.insert(params.ds_id, new_reserve);

        Ok(amount_out)
    }

    fn calculate_output(&self, amount_in: u64, reserve: u64) -> u64 {
        // Constant product formula approximation
        let k = reserve * 1000;
        let new_reserve = reserve + amount_in;
        k.checked_div(new_reserve).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sell_ds_with_slippage_protection() {
        let mut router = FlashSwapRouter::new();
        router.set_reserve(1, 10_000);

        let params = SellDsParams {
            ds_id: 1,
            amount_in: 100,
            amount_out_min: 900,  // Require at least 900 out
            deadline: 1000,
        };

        let result = router.sell_ds_reserve(&params, 500);
        assert!(result.is_ok());
        let out = result.unwrap();
        assert!(out >= 900, "Output {} should meet minimum", out);
    }

    #[test]
    fn test_slippage_protection_reverts() {
        let mut router = FlashSwapRouter::new();
        router.set_reserve(1, 10_000);

        let params = SellDsParams {
            ds_id: 1,
            amount_in: 100,
            amount_out_min: 10_000,  // Unreasonably high minimum
            deadline: 1000,
        };

        let result = router.sell_ds_reserve(&params, 500);
        assert!(result.is_err());
    }
}