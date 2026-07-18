use std::cmp;

/// Clean: LP join with proportional ratio check and slippage protection
/// Prevents sandwich attack by enforcing minimum LP out AND max token in
pub struct Pool {
    pub reserve0: u128,
    pub reserve1: u128,
    pub supply: u128,
}

pub struct JoinParams {
    pub max_token0_in: u128,
    pub max_token1_in: u128,
    pub min_lp_out: u128,
}

impl Pool {
    pub fn new(reserve0: u128, reserve1: u128, supply: u128) -> Self {
        Self { reserve0, reserve1, supply }
    }

    /// Clean: Enforces proportional deposit with both min LP AND max token constraints
    pub fn join_pool(&self, params: &JoinParams) -> Option<(u128, u128, u128)> {
        if self.reserve0 == 0 || self.reserve1 == 0 || self.supply == 0 {
            return None;
        }

        // Calculate LP tokens using proportional formula with BOTH constraints
        let lp_from_0 = params.max_token0_in.checked_mul(self.supply)?.checked_div(self.reserve0)?;
        let lp_from_1 = params.max_token1_in.checked_mul(self.supply)?.checked_div(self.reserve1)?;

        // Take MINIMUM to ensure neither token exceeds max input
        let lp_to_mint = cmp::min(lp_from_0, lp_from_1);

        // Enforce minimum LP output (slippage protection)
        if lp_to_mint < params.min_lp_out {
            return None;
        }

        // Calculate actual token amounts based on LP to mint
        let token0_in = lp_to_mint.checked_mul(self.reserve0)?.checked_div(self.supply)?;
        let token1_in = lp_to_mint.checked_mul(self.reserve1)?.checked_div(self.supply)?;

        // Verify within user-specified maximums
        if token0_in > params.max_token0_in || token1_in > params.max_token1_in {
            return None;
        }

        Some((token0_in, token1_in, lp_to_mint))
    }
}

fn main() {
    let pool = Pool::new(1000, 2000, 100);
    let params = JoinParams {
        max_token0_in: 100,
        max_token1_in: 200,
        min_lp_out: 9,
    };
    let result = pool.join_pool(&params);
    assert!(result.is_some());
    let (t0, t1, lp) = result.unwrap();
    assert_eq!(t0, 100);
    assert_eq!(t1, 200);
    assert_eq!(lp, 10);
}