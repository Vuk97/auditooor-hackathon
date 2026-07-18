use std::collections::HashMap;

/// A fee distributor that distributes donations proportionally
/// to current in-range liquidity WITHOUT time-lock protection.
/// VULNERABLE: Same-transaction sandwich attack on donations.
pub struct VulnerableFeeDistributor {
    /// Total liquidity in range (current snapshot only)
    total_liquidity: u128,
    /// Position data: liquidity amount
    positions: HashMap<u64, u128>,
    /// Accumulated fees per unit of liquidity
    fee_growth_global: u128,
    /// Snapshots of fee growth at position entry
    fee_growth_snapshots: HashMap<u64, u128>,
}

impl VulnerableFeeDistributor {
    pub fn new() -> Self {
        Self {
            total_liquidity: 0,
            positions: HashMap::new(),
            fee_growth_global: 0,
            fee_growth_snapshots: HashMap::new(),
        }
    }

    /// Add liquidity - no time tracking
    pub fn add_liquidity(&mut self, position_id: u64, amount: u128) {
        self.positions.insert(position_id, amount);
        self.fee_growth_snapshots.insert(position_id, self.fee_growth_global);
        self.total_liquidity += amount;
    }

    /// Remove liquidity
    pub fn remove_liquidity(&mut self, position_id: u64) -> u128 {
        let amount = self.positions.remove(&position_id).unwrap_or(0);
        self.total_liquidity -= amount;
        amount
    }

    /// Collect fees - NO anti-sandwich check!
    /// VULNERABLE: Fresh positions immediately receive donation-proportional fees
    pub fn collect_fees(&mut self, position_id: u64) -> u128 {
        let liquidity = *self.positions.get(&position_id)?;
        
        // VULNERABLE: No check for how long position existed
        // MEV searcher can: add_liquidity -> donate -> collect_fees -> remove_liquidity
        // all in one transaction, capturing donation fees without real exposure
        
        let fee_growth_delta = self.fee_growth_global - self.fee_growth_snapshots.get(&position_id).unwrap_or(&0);
        let fees = (liquidity as u128).wrapping_mul(fee_growth_delta) / (1u128 << 128).max(1);
        
        self.fee_growth_snapshots.insert(position_id, self.fee_growth_global);
        fees
    }

    /// Donate fees - distributes proportionally to ALL current liquidity
    /// VULNERABLE: Includes positions added in same transaction
    pub fn donate(&mut self, amount: u128) {
        if self.total_liquidity > 0 {
            self.fee_growth_global += (amount << 128) / self.total_liquidity;
        }
    }

    /// EXACT ATTACK: Single-transaction sandwich
    pub fn execute_sandwich_attack(&mut self, attacker_position: u64) -> u128 {
        // Step 1: Add huge liquidity
        self.add_liquidity(attacker_position, 1_000_000);
        
        // Step 2: Trigger donation (e.g., from swap fees or direct donate)
        self.donate(10_000);
        
        // Step 3: Immediately collect fees proportional to our liquidity
        let stolen_fees = self.collect_fees(attacker_position);
        
        // Step 4: Remove liquidity, exit with profit
        self.remove_liquidity(attacker_position);
        
        stolen_fees
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandwich_attack_succeeds() {
        let mut dist = VulnerableFeeDistributor::new();
        
        // Victim has small position
        dist.add_liquidity(999, 100);
        
        // Attacker executes sandwich in single tx
        let stolen = dist.execute_sandwich_attack(1);
        
        // Attack succeeds - captured donation fees without holding risk
        assert!(stolen > 0);
        
        // Victim's fees are diluted
        let victim_fees = dist.collect_fees(999);
        // Victim gets tiny share because attacker dominated during donate
        assert!(victim_fees < stolen);
    }
}