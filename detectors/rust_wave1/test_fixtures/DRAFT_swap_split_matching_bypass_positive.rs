use soroban_sdk::{contract, contractimpl};

const ONE: u128 = 1_000_000;

#[contract]
pub struct OrderBook;

#[contractimpl]
impl OrderBook {
    pub fn match_split_fill(
        fill_amount: u128,
        yes_price: u128,
        no_price: u128,
        notional_so_far: u128,
    ) -> u128 {
        let price_sum = yes_price + no_price;
        if price_sum >= ONE {
            if notional_so_far >= fill_amount {
                0
            } else {
                fill_amount - notional_so_far
            }
        } else {
            fill_amount
        }
    }
}
