use alloy_primitives::{Address, U256};
use std::collections::HashMap;

/// Minimal ERC20 interface for demonstration
pub trait IERC20 {
    fn transfer_from(&mut self, from: Address, to: Address, amount: U256) -> bool;
    fn transfer(&mut self, to: Address, amount: U256) -> bool;
    fn safe_transfer(&mut self, to: Address, amount: U256) -> bool;
}

/// Mock ERC20 implementation for vulnerable pattern
pub struct MockERC20;

impl IERC20 for MockERC20 {
    fn transfer_from(&mut self, from: Address, to: Address, amount: U256) -> bool {
        true
    }
    fn transfer(&mut self, to: Address, amount: U256) -> bool {
        true
    }
    fn safe_transfer(&mut self, to: Address, amount: U256) -> bool {
        true
    }
}

/// Hook settlement that INCORRECTLY uses ERC20 for native tokens
pub struct VulnerableHookSettlement {
    token: MockERC20,
    balances: HashMap<Address, U256>,
}

impl VulnerableHookSettlement {
    pub fn new() -> Self {
        Self {
            token: MockERC20,
            balances: HashMap::new(),
        }
    }
    
    /// VULNERABLE: uses IERC20.transferFrom / safeTransfer for native token case
    pub fn settle(
        &mut self,
        token: Address,
        amount: U256,
        is_native: bool,
        from: Address,
        recipient: Address,
    ) -> bool {
        // BUG: No branch for native token - always uses ERC20 path!
        // This will revert or lose funds when settling native ETH
        self.token.transfer_from(from, recipient, amount)
    }
    
    /// Another vulnerable variant using safeTransfer
    pub fn settle_safe(
        &mut self,
        token: Address,
        amount: U256,
        is_native: bool,
        recipient: Address,
    ) -> bool {
        // BUG: Again no native token handling
        self.token.safe_transfer(recipient, amount)
    }
    
    /// Vulnerable: conditional that still uses ERC20 for native
    pub fn settle_conditional(
        &mut self,
        token: Address,
        amount: U256,
        is_native: bool,
        from: Address,
        recipient: Address,
    ) -> bool {
        if is_native {
            // BUG: Still uses ERC20 transfer for native token!
            self.token.transfer_from(from, recipient, amount)
        } else {
            self.token.transfer_from(from, recipient, amount)
        }
    }
}

fn main() {
    let mut hook = VulnerableHookSettlement::new();
    let token = Address::from([0u8; 20]);
    let from = Address::from([2u8; 20]);
    let recipient = Address::from([1u8; 20]);
    
    // This will fail for native token - uses ERC20 path incorrectly
    let result = hook.settle(token, U256::from(100), true, from, recipient);
    assert!(result); // Compiles but wrong behavior at runtime
}