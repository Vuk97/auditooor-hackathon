// Fixture: state BEFORE the revert commit (the guard fn exists here).
// Used by test_reverted_guard_mine_rust_go.py to build a synthetic Rust repo.
// The guard fn validate_supply_cap is present in this commit.

pub struct Vault {
    pub balance: u64,
}

impl Vault {
    /// Guard: rejects deposits that would push total supply above the cap.
    pub fn validate_supply_cap(&self, amount: u64, cap: u64) -> Result<(), &'static str> {
        if self.balance.saturating_add(amount) > cap {
            return Err("supply cap exceeded");
        }
        Ok(())
    }

    pub fn deposit(&mut self, amount: u64, cap: u64) -> Result<(), &'static str> {
        self.validate_supply_cap(amount, cap)?;
        self.balance += amount;
        Ok(())
    }
}
