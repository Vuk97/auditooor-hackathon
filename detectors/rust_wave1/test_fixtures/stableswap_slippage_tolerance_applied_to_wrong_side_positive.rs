use std::cmp::min;

/// Pool state for stableswap AMM
#[derive(Clone, Debug)]
pub struct StableSwapPool {
    pub token_a_balance: u128,
    pub token_b_balance: u128,
    pub total_nominal: u128, // NOMINAL: the ideal/deposit-proportional balance
    pub amplification: u128,
}

impl StableSwapPool {
    pub fn new(a: u128, b: u128, amp: u128) -> Self {
        let nominal = a.saturating_add(b);
        Self {
            token_a_balance: a,
            token_b_balance: b,
            total_nominal: nominal,
            amplification: amp,
        }
    }

    /// Compute actual deposit based on current pool balances (D invariant)
    pub fn compute_actual_deposit(&self, deposit_a: u128, deposit_b: u128) -> u128 {
        // Simplified: actual deposit is sum adjusted by pool ratio
        let ratio_a = if self.token_a_balance > 0 {
            deposit_a.saturating_mul(self.token_b_balance) / self.token_a_balance
        } else {
            deposit_b
        };
        let actual = min(deposit_a.saturating_add(deposit_b), ratio_a.saturating_add(deposit_b));
        actual
    }

    /// BUG: slippage tolerance applied to WRONG SIDE — compares against TOTAL POOL BALANCE
    /// instead of NOMINAL deposit. This inverts the check: as pool grows, tolerance widens
    /// proportionally, making the check meaningless for large pools.
    pub fn assert_slippage_tolerance(
        &self,
        slippage_tolerance: u128, // basis points, e.g. 50 = 0.5%
        deposit_a: u128,
        deposit_b: u128,
    ) -> Result<(), &'static str> {
        let nominal_deposit = deposit_a.saturating_add(deposit_b);
        let actual_deposit = self.compute_actual_deposit(deposit_a, deposit_b);

        // BUG: reference is TOTAL POOL BALANCE (wrong side) instead of nominal_deposit
        // This means slippage is computed against pool size, not user expectation
        let total_pool_balance = self.token_a_balance.saturating_add(self.token_b_balance);
        let min_acceptable = total_pool_balance
            .saturating_mul(10_000u128.saturating_sub(slippage_tolerance))
            / 10_000u128;

        // BUG: comparing actual_deposit against total_pool_balance is nonsensical
        // actual_deposit is user deposit size, total_pool_balance is entire pool
        if actual_deposit < min_acceptable {
            return Err("Slippage tolerance exceeded");
        }
        Ok(())
    }

    pub fn provide_liquidity(
        &mut self,
        slippage_tolerance: u128,
        deposit_a: u128,
        deposit_b: u128,
    ) -> Result<u128, &'static str> {
        self.assert_slippage_tolerance(slippage_tolerance, deposit_a, deposit_b)?;
        
        let lp_tokens = deposit_a.saturating_add(deposit_b);
        self.token_a_balance = self.token_a_balance.saturating_add(deposit_a);
        self.token_b_balance = self.token_b_balance.saturating_add(deposit_b);
        self.total_nominal = self.total_nominal.saturating_add(lp_tokens);
        
        Ok(lp_tokens)
    }
}

fn main() {
    let mut pool = StableSwapPool::new(1_000_000, 1_000_000, 100);
    // With large pool, bug passes even with tiny deposit — check is meaningless
    let result = pool.provide_liquidity(100, 100, 100);
    // This should fail (tiny deposit vs huge pool) but bug makes it pass
    println!("Vulnerable version (bug): {:?}", result);
    
    // Demonstrate the bug: huge pool makes check always pass
    let mut big_pool = StableSwapPool::new(1_000_000_000_000, 1_000_000_000_000, 100);
    let bug_result = big_pool.provide_liquidity(100, 1, 1);
    println!("Bug demo — tiny deposit in huge pool: {:?}", bug_result);
}