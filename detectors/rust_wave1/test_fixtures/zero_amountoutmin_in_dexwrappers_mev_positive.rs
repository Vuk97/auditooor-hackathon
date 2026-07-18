use std::cmp;

#[derive(Clone, Debug)]
pub struct SwapParams {
    pub amount_in: u64,
    pub amount_out_min: u64,
    pub path: Vec<u64>,
    pub to: u64,
    pub deadline: u64,
}

pub struct DexWrapper;

impl DexWrapper {
    pub fn swap(params: SwapParams) -> Result<u64, &'static str> {
        // BUG: Passes amount_out_min = 0 directly to router with no validation
        // This allows MEV sandwich attacks to extract full slippage
        let amount_out = execute_router_swap(
            params.amount_in,
            0, // HARDCODED ZERO - ignores params.amount_out_min
            &params.path,
            params.to,
            params.deadline,
        )?;
        
        Ok(amount_out)
    }
    
    pub fn swap_with_user_min(params: SwapParams) -> Result<u64, &'static str> {
        // BUG: Passes user-provided value without sanity check
        // If user passes 0 or it's front-run, MEV extracts value
        let amount_out = execute_router_swap(
            params.amount_in,
            params.amount_out_min, // Direct pass-through, could be 0
            &params.path,
            params.to,
            params.deadline,
        )?;
        
        Ok(amount_out)
    }
}

fn execute_router_swap(
    amount_in: u64,
    amount_out_min: u64,
    _path: &[u64],
    _to: u64,
    _deadline: u64,
) -> Result<u64, &'static str> {
    // Simulated router that would execute at market price
    // With amount_out_min = 0, any output is acceptable
    if amount_out_min == 0 {
        // MEV attacker can manipulate this to near-zero
        Ok(amount_in / 100) // 99% extracted by sandwich
    } else {
        Ok(amount_in * 95 / 100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_swap_zero_min() {
        let params = SwapParams {
            amount_in: 10000,
            amount_out_min: 9500, // User expects 95%, but ignored!
            path: vec![1, 2],
            to: 42,
            deadline: 9999999999,
        };
        // Bug: returns ~100 instead of ~9500 due to hardcoded 0
        let result = DexWrapper::swap(params).unwrap();
        assert_eq!(result, 100); // 99% lost to MEV
    }
}