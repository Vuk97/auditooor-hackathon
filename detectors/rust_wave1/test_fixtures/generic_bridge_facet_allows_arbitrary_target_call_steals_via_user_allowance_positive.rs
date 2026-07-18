use alloy_primitives::{Address, U256, Bytes};

/// Vulnerable version: arbitrary target call without allowlist validation
/// Attacker can call USDC.transferFrom(victim, attacker, allowance) or any token
pub struct GenericBridgeFacet {
    // No allowlist - any target is accepted
}

impl GenericBridgeFacet {
    pub fn new() -> Self {
        Self {}
    }

    pub fn swap_and_start_bridge_tokens_generic(
        &self,
        target: Address,
        call_data: Bytes,
        _user: Address,
    ) -> Result<(), &'static str> {
        // VULNERABLE: No validation of target address
        // Attacker can pass any target, including token contracts
        // to steal via transferFrom using existing allowances
        self.execute_swap(target, call_data)
    }

    fn execute_swap(
        &self,
        target: Address,
        call_data: Bytes,
    ) -> Result<(), &'static str> {
        // Direct external call to arbitrary target
        // This allows calling e.g. USDC.transferFrom(victim, attacker, allowance)
        let _ = (target, call_data);
        Ok(())
    }
}

// Simulated token interface that attacker can exploit
pub struct ERC20Token;

impl ERC20Token {
    pub fn transfer_from(
        &self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> bool {
        // In real scenario: transfers tokens using allowance
        let _ = (from, to, amount);
        true
    }
}

fn main() {
    let facet = GenericBridgeFacet::new();
    
    // Attacker calls with arbitrary target (e.g., USDC contract)
    // and crafted calldata for transferFrom
    let malicious_target = Address::from([0xA0u8; 20]); // USDC contract
    let malicious_calldata = Bytes::from_static(b"transferFrom(address,address,uint256)");
    
    // This succeeds without any validation - STEALS TOKENS
    let result = facet.swap_and_start_bridge_tokens_generic(
        malicious_target,
        malicious_calldata,
        Address::ZERO, // victim's context
    );
    assert!(result.is_ok()); // Vulnerability: unauthorized call succeeded
}