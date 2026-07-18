// fixture: negative — checked arithmetic on all lamport/amount values.
fn credit(balance: u64, amount: u64) -> u64 {
    balance.checked_add(amount).expect("overflow")
}

fn debit_fee(lamports: u64, fee: u64) -> u64 {
    lamports.checked_sub(fee).expect("underflow")
}

fn scale_shares(shares: u64, multiplier: u64) -> u64 {
    shares.checked_mul(multiplier).expect("overflow")
}
