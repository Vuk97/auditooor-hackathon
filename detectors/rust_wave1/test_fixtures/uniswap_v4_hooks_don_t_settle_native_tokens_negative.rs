use alloy_primitives::{Address, U256};
use std::collections::HashMap;

/// Minimal ERC20 interface for demonstration
pub trait IERC20 {
    fn transfer_from(&mut self, from: Address, to: Address, amount: U256) -> bool;
    fn transfer(&mut self, to: Address, amount: U256) -> bool;
}

/// Native token wrapper for ETH settlements
pub struct NativeToken;

impl NativeToken {
    pub fn deposit() -> Self {
        Self
    }
    
    pub fn transfer(to: Address, amount: U256) -> bool {
        // In real implementation: call with value
        true
    }
}

/// Hook settlement that CORRECTLY handles native tokens
pub struct HookSettlement {
    balances: HashMap<Address, U256>,
}

impl HookSettlement {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
        }
    }
    
    /// Correct: uses native transfer path for native token
    pub fn settle(
        &mut self,
        token: Address,
        amount: U256,
        is_native: bool,
        recipient: Address,
    ) -> bool {
        if is_native {
            // CORRECT: Use native token transfer, not ERC20 transferFrom
            NativeToken::transfer(recipient, amount)
        } else {
            // ERC20 path: use transferFrom
            self.erc20_settle(token, amount, recipient)
        }
    }
    
    fn erc20_settle(&mut self, token: Address, amount: U256, recipient: Address) -> bool {
        // ERC20 logic here
        true
    }
}

fn main() {
    let mut hook = HookSettlement::new();
    let token = Address::from([0u8; 20]);
    let recipient = Address::from([1u8; 20]);
    
    // Native token settlement - works correctly
    let result = hook.settle(token, U256::from(100), true, recipient);
    assert!(result);
    
    // ERC20 settlement - works correctly
    let result = hook.settle(token, U256::from(200), false, recipient);
    assert!(result);
}