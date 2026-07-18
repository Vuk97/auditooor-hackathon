use std::collections::HashMap;

/// Vulnerable: ETH transferred during rebalance but sgReceive NEVER called.
/// ETH sits in contract balance, stealable by anyone calling wrap/donate.
pub struct MTOFT {
    balances: HashMap<u64, u128>,
    stargate_pool: u64,
    /// ETH held directly in contract (not tracked via sgReceive)
    native_balance: u128,
}

impl MTOFT {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            stargate_pool: 1,
            native_balance: 0,
        }
    }

    /// Rebalance: sends ETH to destination but FORGETS to call sgReceive
    pub fn rebalance_to_remote(
        &mut self,
        dst_chain_id: u64,
        amount: u128,
        dst_mtoft: &mut MTOFT,
    ) -> Result<(), &'static str> {
        // Burn/lock local tokens
        let local_balance = self.balances.entry(dst_chain_id).or_insert(0);
        if *local_balance < amount {
            return Err("insufficient balance");
        }
        *local_balance -= amount;

        // Transfer ETH to destination mTOFT contract
        let eth_transfer = amount;
        
        // VULNERABILITY: ETH is transferred but sgReceive is NOT called!
        // The destination contract receives ETH but never credits it properly.
        // ETH just sits in native_balance, unaccounted for.
        dst_mtoft.native_balance += eth_transfer;
        
        // MISSING: dst_mtoft.sg_receive(...)

        Ok(())
    }

    /// sgReceive exists but is never invoked during rebalancing
    pub fn sg_receive(
        &mut self,
        src_pool: u64,
        src_chain_id: u64,
        amount: u128,
    ) -> Result<(), &'static str> {
        if src_pool != self.stargate_pool {
            return Err("invalid pool");
        }
        let balance = self.balances.entry(src_chain_id).or_insert(0);
        *balance += amount;
        Ok(())
    }

    /// Wrap: uses native_balance directly, no sgReceive credit check!
    /// Anyone can steal the unaccounted ETH.
    pub fn wrap(&mut self, _caller: u64, amount: u128) -> Result<(), &'static str> {
        // BUG: No verification that caller's balance was credited via sgReceive
        if self.native_balance < amount {
            return Err("insufficient native");
        }
        self.native_balance -= amount;
        // Mint wrapped tokens to caller...
        Ok(())
    }

    /// Alternative steal path: direct donation then wrap
    pub fn donate_and_wrap(&mut self, caller: u64, amount: u128) -> Result<(), &'static str> {
        // Anyone can "donate" and immediately wrap the unaccounted ETH
        self.wrap(caller, amount)
    }
}

fn main() {
    let mut src = MTOFT::new();
    let mut dst = MTOFT::new();
    src.balances.insert(2, 1000);
    
    // Rebalance sends ETH but no sgReceive call
    src.rebalance_to_remote(2, 500, &mut dst).unwrap();
    
    // Attacker steals the stranded ETH
    dst.wrap(999, 500).unwrap(); // caller 999 steals all 500 ETH
    assert_eq!(dst.native_balance, 0);
}