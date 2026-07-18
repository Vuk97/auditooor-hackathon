use std::cmp;

/// Vulnerable: LP join with asymmetric min ratio - attacker can sandwich to overpay one side
/// Missing proportional check and min_lp_out allows sandwich to extract value
pub struct Pool {
    pub reserve0: u128,
    pub reserve1: u128,
    pub supply: u128,
}

pub struct JoinParams {
    pub token0_in: u128,
    pub token1_in: u128,
}

impl Pool {
    pub fn new(reserve0: u128, reserve1: u128, supply: u128) -> Self {
        Self { reserve0, reserve1, supply }
    }

    /// VULNERABLE: Uses min of two ratios without verifying proportional deposit
    /// Attacker sandwiches: front-run to skew reserves, victim overpays one side
    pub fn on_join_pool(&self, params: &JoinParams) -> Option<u128> {
        if self.reserve0 == 0 || self.reserve1 == 0 || self.supply == 0 {
            return None;
        }

        // BUG: min() allows asymmetric deposit - one token can be wildly overprovided
        // No check that token0_in/token1_in matches reserve0/reserve1 ratio
        let amount_lp = cmp::min(
            params.token0_in.checked_mul(self.supply)?.checked_div(self.reserve0)?,
            params.token1_in.checked_mul(self.supply)?.checked_div(self.reserve1)?,
        );

        // No min_lp_out slippage check - attacker can make LP amount arbitrarily small
        // No verification that actual token amounts are proportional to reserves

        Some(amount_lp)
    }
}

fn main() {
    // Simulate sandwich attack:
    // 1. Attacker front-runs to skew reserves from 1000:2000 to 100:20000 (manipulated)
    let attacked_pool = Pool::new(100, 20000, 100);
    
    // Victim deposits thinking pool is balanced, provides 100:200 (1:2 ratio)
    // But actual reserves are 1:200, so victim massively overpays token1
    let victim_params = JoinParams {
        token0_in: 100,
        token1_in: 200,
    };
    
    let lp_out = attacked_pool.on_join_pool(&victim_params).unwrap();
    // Victim gets min(100*100/100, 200*100/20000) = min(100, 1) = 1 LP
    // But provided 100 token0 worth ~100 and 200 token1 worth ~200 in fair pool
    // Actually lost ~99% of token0 value due to asymmetric min
    assert_eq!(lp_out, 1);
}