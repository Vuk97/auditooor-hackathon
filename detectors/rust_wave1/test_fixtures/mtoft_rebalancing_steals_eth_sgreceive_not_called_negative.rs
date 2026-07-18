use std::collections::HashMap;

/// Clean: sgReceive is properly called on destination chain after ETH transfer
/// This ensures ETH is accounted for and not left stealable in the contract.
pub struct MTOFT {
    balances: HashMap<u64, u128>,
    stargate_pool: u64,
}

impl MTOFT {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            stargate_pool: 1,
        }
    }

    /// Rebalance: sends ETH to destination and properly triggers sgReceive
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
        
        // CRITICAL FIX: Call sgReceive on destination to credit the ETH properly
        dst_mtoft.sg_receive(
            self.stargate_pool,
            dst_chain_id,
            eth_transfer,
        )?;

        Ok(())
    }

    /// sgReceive: properly credited, auth-gated, records received ETH
    pub fn sg_receive(
        &mut self,
        src_pool: u64,
        src_chain_id: u64,
        amount: u128,
    ) -> Result<(), &'static str> {
        // Only callable by Stargate router (simulated check)
        if src_pool != self.stargate_pool {
            return Err("invalid pool");
        }
        
        let balance = self.balances.entry(src_chain_id).or_insert(0);
        *balance += amount;
        
        Ok(())
    }

    /// Wrap: requires prior balance credit via sgReceive
    pub fn wrap(&mut self, caller: u64, amount: u128) -> Result<(), &'static str> {
        let balance = self.balances.get(&caller).copied().unwrap_or(0);
        if balance < amount {
            return Err("no credited balance");
        }
        // Proceed with wrap...
        Ok(())
    }
}

fn main() {
    let mut src = MTOFT::new();
    let mut dst = MTOFT::new();
    src.balances.insert(2, 1000);
    src.rebalance_to_remote(2, 500, &mut dst).unwrap();
    assert_eq!(dst.balances.get(&1).copied().unwrap_or(0), 500);
}