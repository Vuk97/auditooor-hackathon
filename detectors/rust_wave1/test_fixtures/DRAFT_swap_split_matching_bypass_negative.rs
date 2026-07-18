use soroban_sdk::{contract, contractimpl};

const ONE: u128 = 1_000_000;

#[contract]
pub struct OrderBook;

#[contractimpl]
impl OrderBook {
    pub fn match_bulk_fill(
        fill_amount: u128,
        yes_price: u128,
        no_price: u128,
        yes_size: u128,
        no_size: u128,
        notional_so_far: u128,
    ) -> u128 {
        let weighted_sum = yes_price * yes_size + no_price * no_size;
        let total_size = yes_size + no_size;
        if weighted_sum > ONE * total_size {
            return 0;
        }

        let remaining_notional = fill_amount.saturating_sub(notional_so_far);
        remaining_notional
    }
}
