use alloy_primitives::{Address, U256, Bytes};
use std::collections::HashSet;

/// Clean version: target is validated against an allowlist before call
pub struct GenericBridgeFacet {
    allowed_targets: HashSet<Address>,
}

impl GenericBridgeFacet {
    pub fn new() -> Self {
        Self {
            allowed_targets: HashSet::new(),
        }
    }

    pub fn add_allowed_target(&mut self, target: Address) {
        self.allowed_targets.insert(target);
    }

    pub fn swap_and_start_bridge_tokens_generic(
        &mut self,
        target: Address,
        call_data: Bytes,
        user: Address,
    ) -> Result<(), &'static str> {
        // SECURITY: Validate target is in allowlist
        if !self.allowed_targets.contains(&target) {
            return Err("Target not in allowlist");
        }

        // Now safe to perform the swap with validated target
        self.execute_swap(target, call_data, user)
    }

    fn execute_swap(
        &self,
        target: Address,
        call_data: Bytes,
        _user: Address,
    ) -> Result<(), &'static str> {
        // Simulate external call to validated target
        let _ = (target, call_data);
        Ok(())
    }
}

fn main() {
    let mut facet = GenericBridgeFacet::new();
    let allowed = Address::ZERO;
    facet.add_allowed_target(allowed);
    
    let result = facet.swap_and_start_bridge_tokens_generic(
        allowed,
        Bytes::new(),
        Address::ZERO,
    );
    assert!(result.is_ok());
    
    // Unauthorized target should fail
    let unauthorized = Address::from([1u8; 20]);
    let result = facet.swap_and_start_bridge_tokens_generic(
        unauthorized,
        Bytes::new(),
        Address::ZERO,
    );
    assert!(result.is_err());
}