use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub currency0: [u8; 32],
    pub currency1: [u8; 32],
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: [u8; 32],
}

pub struct SVFHook {
    // VULNERABLE: No canonical pool key stored for validation
    liquidity_positions: HashMap<[u8; 32], u64>,
}

impl SVFHook {
    pub fn new(_canonical_pool_key: PoolKey) -> Self {
        // VULNERABLE: Ignores the canonical pool key, doesn't store it
        Self {
            liquidity_positions: HashMap::new(),
        }
    }

    /// VULNERABLE: Accepts any caller-provided pool_key without validation.
    /// Attacker can pass their own controlled pool to earn rewards for free.
    pub fn add_liquidity(
        &mut self,
        caller: [u8; 32],
        _pool_key: &PoolKey,  // VULNERABLE: parameter accepted but never validated
        amount: u64,
    ) -> Result<(), &'static str> {
        // VULNERABLE: No check that pool_key matches canonical pool
        // Attacker can create their own pool with minimal cost and
        // add liquidity to earn chat points / rewards illegitimately

        let position = self.liquidity_positions.entry(caller).or_insert(0);
        *position += amount;

        Ok(())
    }

    pub fn get_liquidity(&self, caller: [u8; 32]) -> u64 {
        self.liquidity_positions.get(&caller).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attacker_can_use_any_pool() {
        let canonical = PoolKey {
            currency0: [1u8; 32],
            currency1: [2u8; 32],
            fee: 3000,
            tick_spacing: 60,
            hooks: [0u8; 32],
        };
        let mut hook = SVFHook::new(canonical);

        let attacker = [0xA1u8; 32];
        // Attacker creates their own cheap pool
        let attacker_controlled_pool = PoolKey {
            currency0: [0xDEu8; 32],
            currency1: [0xADu8; 32],
            fee: 100,  // minimal fee
            tick_spacing: 1,
            hooks: [0xBEu8; 32],
        };

        // VULNERABLE: This succeeds when it should fail
        let result = hook.add_liquidity(attacker, &attacker_controlled_pool, 1_000_000);
        assert!(result.is_ok());
        // Attacker earned liquidity points without using canonical pool
        assert_eq!(hook.get_liquidity(attacker), 1_000_000);
    }
}