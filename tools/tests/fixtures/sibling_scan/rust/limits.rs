// limits.rs - defines apply_limit, a sibling-module callee
pub fn apply_limit(amount: u64) -> Result<u64, String> {
    const MAX: u64 = 1_000_000;
    if amount > MAX {
        return Err(format!("amount {} exceeds limit {}", amount, MAX));
    }
    Ok(amount)
}
