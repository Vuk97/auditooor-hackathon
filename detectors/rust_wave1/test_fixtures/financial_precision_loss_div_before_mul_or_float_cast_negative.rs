pub fn compute_tx_fee_amount_ok(total_amount: u128, gas_provided: u128, gas_used: u128) -> u128 {
    let tx_fee_amount = total_amount * gas_used / gas_provided;
    tx_fee_amount
}

pub fn compute_quote_price_ok(price_amount: u128, reserve_amount: u128, quote_amount: u128) -> u128 {
    let quote_price = price_amount
        .checked_mul(quote_amount)
        .unwrap_or(0)
        .checked_div(reserve_amount)
        .unwrap_or(0);
    quote_price
}

pub fn compute_fee_amount_with_literal_scale_ok(total_amount: u128, fee_bps: u128) -> u128 {
    let fee_amount = total_amount * fee_bps / 10_000u128;
    fee_amount
}

pub fn compute_samples_for_preview(samples: u64, width: u64, height: u64) -> u64 {
    let scaled = samples / width * height;
    let root = (samples as f64).sqrt() as u64;
    scaled + root
}
