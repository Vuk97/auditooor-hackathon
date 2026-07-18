use std::collections::HashMap;

/// Safe withdrawal finalizer that caps gas to prevent 63/64 rule bypass.
pub struct WithdrawalPortal {
    withdrawals: HashMap<[u8; 32], Withdrawal>,
    min_gas_reserve: u64,
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
            min_gas_reserve: 100_000,
        }
    }

    pub fn finalize_withdrawal(&mut self, id: [u8; 32]) -> Result<(), &'static str> {
        let withdrawal = self.withdrawals.get(&id).ok_or("unknown withdrawal")?;
        
        // SAFE: Cap gas limit and enforce minimum reserve for post-call execution
        let effective_gas = std::cmp::min(withdrawal.gas_limit, 1_000_000);
        let gas_needed = effective_gas.saturating_add(self.min_gas_reserve);
        
        // Ensure sufficient gas remains for this call frame after 63/64 forwarding
        let available_gas = self.remaining_gas();
        if gas_needed > available_gas {
            return Err("insufficient gas for safe execution");
        }
        
        // Forward capped gas to callback, keeping reserve for post-call logic
        self.execute_callback(withdrawal.target, withdrawal.amount, effective_gas)?;
        
        // Post-call state updates guaranteed to execute
        self.withdrawals.remove(&id);
        self.record_finalization(&id);
        
        Ok(())
    }

    fn remaining_gas(&self) -> u64 {
        // Simplified: in real system would query remaining gas
        10_000_000
    }

    fn execute_callback(&mut self, _target: [u8; 20], _amount: u64, _gas: u64) -> Result<(), &'static str> {
        // Simplified external call with forwarded gas
        Ok(())
    }

    fn record_finalization(&mut self, _id: &[u8; 32]) {
        // State update that must not be skipped
    }
}