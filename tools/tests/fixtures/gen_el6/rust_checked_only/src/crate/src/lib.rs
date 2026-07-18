pub fn total(balance: u64, amount: u64) -> Option<u64> {
    let new_balance = balance.checked_add(amount)?;
    Some(new_balance)
}
