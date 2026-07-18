// Fixture: state AFTER the revert commit (the guard fn was removed).
// validate_supply_cap is gone — this is the audit-pin state for the Rust
// reverted-guard synthetic test. The live code has no supply-cap guard.

pub struct Vault {
    pub balance: u64,
}

impl Vault {
    pub fn deposit(&mut self, amount: u64, _cap: u64) -> Result<(), &'static str> {
        // Guard was here; reverted by "Trust mitigations" commit.
        self.balance += amount;
        Ok(())
    }
}
