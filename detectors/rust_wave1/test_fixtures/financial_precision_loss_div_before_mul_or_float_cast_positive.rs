pub fn compute_tx_fee_amount_bad(total_amount: u128, gas_provided: u128, gas_used: u128) -> u128 {
    let tx_fee_amount = total_amount / gas_provided * gas_used;
    tx_fee_amount
}

pub fn estimate_quote_price_bad(price_amount: u128, reserve_amount: u128, quote_amount: u128) -> u128 {
    let quote_price = price_amount
        .checked_div(reserve_amount)
        .unwrap_or(0)
        .checked_mul(quote_amount)
        .unwrap_or(0);
    quote_price
}

pub fn compute_fee_amount_with_literal_scale_bad(total_amount: u128, fee_bps: u128) -> u128 {
    let fee_amount = total_amount / 10_000u128 * fee_bps;
    fee_amount
}

pub fn compute_sqrt_price_amount_bad(price_amount: u128, fee_rate: u128) -> u128 {
    let sqrt_price_amount = ((price_amount as f64).sqrt() * fee_rate as f64) as u128;
    sqrt_price_amount
}
