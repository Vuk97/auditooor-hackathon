use std::collections::HashMap;

/// Native token limit tracking that applies to ALL execution paths
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

    /// Tracks native token spend - called from ALL entry points including executeFromExecutor
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

    /// Execute from executor - ALSO tracks spend (secure)
    pub fn execute_from_executor(
        &mut self,
        account: [u8; 32],
        value: u64,
        _data: &[u8],
    ) -> Result<(), &'static str> {
        // CRITICAL: spend tracking applied consistently
        self.track_spend(account, value)?;
        // ... execution logic
        Ok(())
    }

    /// Direct execution - also tracks spend
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
    
    // All paths properly tracked
    module.validate_user_op(account, 100).unwrap();
    module.execute_from_executor(account, 200, b"test").unwrap();
    module.execute(account, 300, b"test").unwrap();
    
    // Would fail: module.execute_from_executor(account, 500, b"test").unwrap();
}