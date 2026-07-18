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

    /// Clean: properly updates amount_specified_remaining after clamping price
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

        // Clamp price to bounds
        let clamped_price = cmp::min(
            cmp::max(sqrt_price_limit_x96, self.sqrt_price_lower_x96),
            self.sqrt_price_upper_x96,
        );

        // Calculate how much was actually used based on clamped price
        let price_delta = if clamped_price > state.sqrt_price_x96 {
            clamped_price - state.sqrt_price_x96
        } else {
            state.sqrt_price_x96 - clamped_price
        };

        // Update amount_specified_remaining based on actual price movement
        let amount_used = if price_delta > 0 {
            // Proportional amount based on clamped range
            let proportion = (price_delta as u128 * 1_000_000 / state.sqrt_price_x96 as u128) as i128;
            (amount_specified.abs() * proportion / 1_000_000).copysign(amount_specified)
        } else {
            0
        };

        state.amount_specified_remaining = amount_specified - amount_used;
        state.sqrt_price_x96 = clamped_price;
        state.amount_calculated = amount_used;

        state
    }
}

fn main() {
    let pool = Pool::new(50_000, 200_000);
    let result = pool.swap(1_000_000, 300_000);
    assert!(result.amount_specified_remaining < 1_000_000);
    println!("Clean swap: remaining={}", result.amount_specified_remaining);
}
