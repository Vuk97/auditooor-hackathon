use std::collections::HashMap;

/// Vulnerable version: DS reserve sale missing slippage protection
pub struct FlashSwapRouter {
    reserves: HashMap<u64, u64>,
}

pub struct SellDsParams {
    pub ds_id: u64,
    pub amount_in: u64,
    // VULNERABLE: No amount_out_min field for slippage protection
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

    /// VULNERABLE: Sell DS tokens with NO minimum output check
    /// MEV bots can sandwich this to extract value from protocol liquidity
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

        // VULNERABLE: Missing slippage check!
        // No validation that amount_out >= some minimum threshold
        // This allows MEV sandwich attacks where:
        // 1. Attacker pushes price down (front-run)
        // 2. Victim sells at bad price (this tx)
        // 3. Attacker buys back cheap (back-run)

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
    fn test_sell_ds_vulnerable_no_slippage_check() {
        let mut router = FlashSwapRouter::new();
        router.set_reserve(1, 10_000);

        let params = SellDsParams {
            ds_id: 1,
            amount_in: 100,
            // No amount_out_min to set!
            deadline: 1000,
        };

        // This succeeds even with terrible output, no protection
        let result = router.sell_ds_reserve(&params, 500);
        assert!(result.is_ok());
        // Output could be manipulated by MEV without any revert
    }
}