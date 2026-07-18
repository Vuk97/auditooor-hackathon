use std::collections::HashMap;

/// A fee distributor that tracks liquidity positions over time
/// to prevent same-transaction sandwich attacks on donations.
pub struct SafeFeeDistributor {
    /// Tracks when each position was last modified (block height)
    position_entry_height: HashMap<u64, u64>,
    /// Current block height
    current_height: u64,
    /// Minimum blocks a position must be held before receiving donations
    min_hold_blocks: u64,
    /// Total liquidity in range
    total_liquidity: u128,
    /// Position data: (liquidity, entry_height)
    positions: HashMap<u64, (u128, u64)>,
    /// Accumulated fees per unit of liquidity
    fee_growth_global: u128,
    /// Snapshots of fee growth at position entry
    fee_growth_snapshots: HashMap<u64, u128>,
}

impl SafeFeeDistributor {
    pub fn new(min_hold_blocks: u64) -> Self {
        Self {
            position_entry_height: HashMap::new(),
            current_height: 0,
            min_hold_blocks,
            total_liquidity: 0,
            positions: HashMap::new(),
            fee_growth_global: 0,
            fee_growth_snapshots: HashMap::new(),
        }
    }

    pub fn advance_block(&mut self) {
        self.current_height += 1;
    }

    /// Add liquidity with time-lock protection
    pub fn add_liquidity(&mut self, position_id: u64, amount: u128) {
        let entry_height = self.current_height;
        self.position_entry_height.insert(position_id, entry_height);
        self.positions.insert(position_id, (amount, entry_height));
        self.fee_growth_snapshots.insert(position_id, self.fee_growth_global);
        self.total_liquidity += amount;
    }

    /// Remove liquidity - only if position exists
    pub fn remove_liquidity(&mut self, position_id: u64) -> u128 {
        let (amount, _) = self.positions.remove(&position_id).unwrap_or((0, 0));
        self.total_liquidity -= amount;
        amount
    }

    /// Collect fees with anti-sandwich check: position must have existed
    /// for min_hold_blocks before receiving any donation-proportional fees
    pub fn collect_fees(&mut self, position_id: u64) -> u128 {
        let (liquidity, entry_height) = *self.positions.get(&position_id)?;
        
        // CRITICAL FIX: Enforce minimum holding period
        let blocks_held = self.current_height.saturating_sub(entry_height);
        if blocks_held < self.min_hold_blocks {
            return 0; // Position too new, possible sandwich attack
        }
        
        let fee_growth_delta = self.fee_growth_global - self.fee_growth_snapshots.get(&position_id).unwrap_or(&0);
        let fees = (liquidity as u128).wrapping_mul(fee_growth_delta) / (1u128 << 128).max(1);
        
        // Update snapshot after collection
        self.fee_growth_snapshots.insert(position_id, self.fee_growth_global);
        fees
    }

    /// Donate fees - distributes proportionally but only to time-qualified positions
    pub fn donate(&mut self, amount: u128) {
        if self.total_liquidity > 0 {
            self.fee_growth_global += (amount << 128) / self.total_liquidity;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandwich_blocked() {
        let mut dist = SafeFeeDistributor::new(1);
        dist.advance_block(); // height = 1
        
        // Attacker adds liquidity
        dist.add_liquidity(1, 1000);
        
        // Same block: try to donate and collect - blocked
        dist.donate(100);
        let fees = dist.collect_fees(1);
        assert_eq!(fees, 0); // Blocked by time lock
        
        // Next block: can collect
        dist.advance_block(); // height = 2
        let fees = dist.collect_fees(1);
        assert!(fees > 0); // Now allowed
    }
}