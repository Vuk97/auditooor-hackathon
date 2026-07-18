// fixture: positive — bare arithmetic on lamport/amount/balance values.
fn credit(balance: u64, amount: u64) -> u64 {
    let new_balance = balance + amount;
    new_balance
}

fn debit_fee(lamports: u64, fee: u64) -> u64 {
    lamports - fee
}

fn scale_shares(shares: u64, multiplier: u64) -> u64 {
    let total = shares * multiplier;
    total
}
