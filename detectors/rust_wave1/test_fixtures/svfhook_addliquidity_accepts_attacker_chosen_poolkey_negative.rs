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
    canonical_pool_key: PoolKey,
    liquidity_positions: HashMap<[u8; 32], u64>,
}

impl SVFHook {
    pub fn new(canonical_pool_key: PoolKey) -> Self {
        Self {
            canonical_pool_key,
            liquidity_positions: HashMap::new(),
        }
    }

    /// Validates that caller-provided pool_key matches the canonical pool.
    /// Only allows liquidity additions to the authorized pool.
    pub fn add_liquidity(
        &mut self,
        caller: [u8; 32],
        pool_key: &PoolKey,
        amount: u64,
    ) -> Result<(), &'static str> {
        // SECURITY: Enforce caller must use the canonical pool key
        if pool_key != &self.canonical_pool_key {
            return Err("Invalid pool key: must use canonical pool");
        }

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
    fn test_only_canonical_pool_allowed() {
        let canonical = PoolKey {
            currency0: [1u8; 32],
            currency1: [2u8; 32],
            fee: 3000,
            tick_spacing: 60,
            hooks: [0u8; 32],
        };
        let mut hook = SVFHook::new(canonical.clone());

        let caller = [3u8; 32];
        let result = hook.add_liquidity(caller, &canonical, 1000);
        assert!(result.is_ok());
        assert_eq!(hook.get_liquidity(caller), 1000);

        // Attempt with wrong pool key should fail
        let malicious_pool = PoolKey {
            currency0: [99u8; 32],
            currency1: [88u8; 32],
            fee: 3000,
            tick_spacing: 60,
            hooks: [0u8; 32],
        };
        let result = hook.add_liquidity(caller, &malicious_pool, 2000);
        assert!(result.is_err());
        // Liquidity should NOT increase
        assert_eq!(hook.get_liquidity(caller), 1000);
    }
}