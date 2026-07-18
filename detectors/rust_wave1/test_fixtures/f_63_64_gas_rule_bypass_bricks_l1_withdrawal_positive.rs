use std::collections::HashMap;

/// Vulnerable withdrawal finalizer: forwards uncapped gasLimit, allowing
/// 63/64 rule to leave insufficient gas for post-call resumption.
pub struct WithdrawalPortal {
    withdrawals: HashMap<[u8; 32], Withdrawal>,
}

struct Withdrawal {
    target: [u8; 20],
    amount: u64,
    gas_limit: u64,
}

impl WithdrawalPortal {
    pub fn new() -> Self {
        Self {
            withdrawals: HashMap::new(),
        }
    }

    pub fn finalize_withdrawal(&mut self, id: [u8; 32]) -> Result<(), &'static str> {
        let withdrawal = self.withdrawals.get(&id).ok_or("unknown withdrawal")?;
        
        // VULNERABLE: Forwards full gas_limit without cap or reserve check.
        // Attacker submits gas_limit near block gas limit. After 63/64 rule,
        // callback receives ~63/64 * gas_limit, leaving < 1/64 for this frame.
        // If callback consumes most of its gas, post-call operations revert.
        self.execute_callback(withdrawal.target, withdrawal.amount, withdrawal.gas_limit)?;
        
        // CRITICAL: These operations may revert due to out-of-gas, bricking withdrawal
        self.withdrawals.remove(&id);
        self.record_finalization(&id);
        
        Ok(())
    }

    fn execute_callback(&mut self, _target: [u8; 20], _amount: u64, gas_limit: u64) -> Result<(), &'static str> {
        // Simplified: in real EVM, this would be CALL with gas=gas_limit
        // 63/64 rule applies: only 63/64 of remaining gas is forwarded
        let _forwarded_gas = gas_limit * 63 / 64;
        // If gas_limit is huge, remaining 1/64 may be insufficient for caller
        Ok(())
    }

    fn record_finalization(&mut self, _id: &[u8; 32]) {
        // State update that gets skipped on out-of-gas, permanently bricking withdrawal
    }
}