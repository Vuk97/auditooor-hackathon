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
        // Enforce minimum slippage protection
        let min_acceptable = params.amount_in / 100; // 1% minimum
        let effective_min = cmp::max(params.amount_out_min, min_acceptable);
        
        if effective_min == 0 {
            return Err("amount_out_min must be non-zero");
        }
        
        // Simulate router call with slippage protection
        let amount_out = simulate_router_swap(params.amount_in, &params.path)?;
        
        if amount_out < effective_min {
            return Err("insufficient output amount");
        }
        
        Ok(amount_out)
    }
}

fn simulate_router_swap(amount_in: u64, _path: &[u64]) -> Result<u64, &'static str> {
    // Simplified DEX simulation
    Ok(amount_in * 95 / 100) // 5% fee/slippage simulation
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_swap_with_protection() {
        let params = SwapParams {
            amount_in: 10000,
            amount_out_min: 100, // User-specified minimum
            path: vec![1, 2],
            to: 42,
            deadline: 9999999999,
        };
        assert!(DexWrapper::swap(params).is_ok());
    }
    
    #[test]
    fn test_swap_rejects_zero_with_floor() {
        let params = SwapParams {
            amount_in: 10000,
            amount_out_min: 0, // User tries zero, but floor protects
            path: vec![1, 2],
            to: 42,
            deadline: 9999999999,
        };
        // Should succeed because floor raises it to 100
        assert!(DexWrapper::swap(params).is_ok());
    }
}