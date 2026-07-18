use std::cmp;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Price {
    pub sqrt_price_x96: u128,
}

#[derive(Clone, Copy, Debug)]
pub struct SwapState {
    pub amount_specified_remaining: i128,
    pub amount_calculated: i128,
    pub sqrt_price_x96: u128,
}

pub struct Pool {
    pub sqrt_price_lower_x96: u128,
    pub sqrt_price_upper_x96: u128,
}

impl Pool {
    pub fn new(lower: u128, upper: u128) -> Self {
        Self {
            sqrt_price_lower_x96: lower,
            sqrt_price_upper_x96: upper,
        }
    }

    /// Vulnerable: clamps price but does NOT update amount_specified_remaining
    /// User pays full amount_specified but only gets clamped-range liquidity
    pub fn swap(
        &self,
        amount_specified: i128,
        sqrt_price_limit_x96: u128,
    ) -> SwapState {
        let mut state = SwapState {
            amount_specified_remaining: amount_specified,
            amount_calculated: 0,
            sqrt_price_x96: 100_000,
        };

        // Clamp price to bounds - but forget to adjust amount
        let clamped_price = cmp::min(
            cmp::max(sqrt_price_limit_x96, self.sqrt_price_lower_x96),
            self.sqrt_price_upper_x96,
        );

        // BUG: amount_specified_remaining is NOT updated after clamping
        // The full amount_specified is consumed, but only clamped_price range is used
        // Excess funds are effectively locked in the contract
        state.sqrt_price_x96 = clamped_price;
        
        // Pretend we used all the amount (wrong!)
        state.amount_calculated = amount_specified;
        // amount_specified_remaining stays at original value, implying nothing left
        // But actually user should get refund for unused portion

        state
    }
}

fn main() {
    let pool = Pool::new(50_000, 200_000);
    let result = pool.swap(1_000_000, 300_000);
    // Bug: amount_specified_remaining should be > 0 due to clamp, but it's 1_000_000
    // (or incorrectly showing as if all was used when it wasn't)
    println!("Vulnerable swap: price clamped to {}, amount_remaining={}", 
             result.sqrt_price_x96, result.amount_specified_remaining);
}
