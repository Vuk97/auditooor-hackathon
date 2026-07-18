use std::collections::HashMap;

/// Native token limit tracking with bypass vulnerability
/// Bug: track_spend only called in validateUserOp, not executeFromExecutor
pub struct NativeTokenLimitModule {
    limits: HashMap<[u8; 32], u64>,
    spent: HashMap<[u8; 32], u64>,
}

impl NativeTokenLimitModule {
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
            spent: HashMap::new(),
        }
    }

    pub fn set_limit(&mut self, account: [u8; 32], limit: u64) {
        self.limits.insert(account, limit);
    }

    /// Tracks native token spend - ONLY called from validateUserOp
    fn track_spend(&mut self, account: [u8; 32], amount: u64) -> Result<(), &'static str> {
        let limit = self.limits.get(&account).copied().unwrap_or(u64::MAX);
        let current = self.spent.entry(account).or_insert(0);
        if *current + amount > limit {
            return Err("native token limit exceeded");
        }
        *current += amount;
        Ok(())
    }

    /// Validate user operation - tracks spend here
    pub fn validate_user_op(&mut self, account: [u8; 32], value: u64) -> Result<(), &'static str> {
        self.track_spend(account, value)
    }

    /// Execute from executor - BYPASSES spend tracking (VULNERABLE)
    /// This is the ERC-6900 executeFromExecutor entry point that skips validation
    pub fn execute_from_executor(
        &mut self,
        account: [u8; 32],
        value: u64,
        _data: &[u8],
    ) -> Result<(), &'static str> {
        // BUG: No track_spend call here! Validation was skipped, so spending
        // goes completely unrecorded, bypassing the limit module.
        // ... execution logic that spends native tokens
        let _ = account; // suppress unused warning
        let _ = value;
        Ok(())
    }

    /// Direct execution - tracks spend (but attacker uses executeFromExecutor)
    pub fn execute(
        &mut self,
        account: [u8; 32],
        value: u64,
        _data: &[u8],
    ) -> Result<(), &'static str> {
        self.track_spend(account, value)?;
        // ... execution logic
        Ok(())
    }
}

fn main() {
    let mut module = NativeTokenLimitModule::new();
    let account = [1u8; 32];
    module.set_limit(account, 1000);
    
    // Legitimate path tracked
    module.validate_user_op(account, 100).unwrap();
    
    // Attacker bypasses limit via executeFromExecutor - unlimited spending!
    // Each call resets nothing, spends nothing from tracked budget
    module.execute_from_executor(account, 5000, b"drain").unwrap(); // over limit!
    module.execute_from_executor(account, 5000, b"drain2").unwrap(); // over limit again!
    module.execute_from_executor(account, 5000, b"drain3").unwrap(); // still works!
    
    // Spent is still 100, but actual spent is 15000+
}