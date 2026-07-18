use std::marker::PhantomData;

// Mock ERC721 interface with safe transfer
pub trait IERC721 {
    fn safe_transfer_from(&mut self, from: Address, to: Address, token_id: U256);
    fn transfer_from(&mut self, from: Address, to: Address, token_id: U256);
}

use alloy_primitives::{Address, U256};

pub struct TokenRecovery<T: IERC721> {
    token: T,
}

pub struct MockERC721;

impl IERC721 for MockERC721 {
    fn safe_transfer_from(&mut self, from: Address, to: Address, token_id: U256) {
        // Safe transfer checks receiver is contract and implements onERC721Received
        let _ = (from, to, token_id);
    }
    
    fn transfer_from(&mut self, from: Address, to: Address, token_id: U256) {
        // Unsafe transfer - no receiver check
        let _ = (from, to, token_id);
    }
}

impl<T: IERC721> TokenRecovery<T> {
    pub fn new(token: T) -> Self {
        Self { token }
    }
    
    /// Recover ERC721 tokens - uses safeTransferFrom to prevent locking
    pub fn recover_erc721(&mut self, to: Address, token_id: U256) {
        let from = Address::ZERO; // simplified
        // CORRECT: Uses safe_transfer_from which prevents tokens from being locked
        // in contracts that don't implement onERC721Received
        self.token.safe_transfer_from(from, to, token_id);
    }
}

fn main() {
    let token = MockERC721;
    let mut recovery = TokenRecovery::new(token);
    recovery.recover_erc721(Address::ZERO, U256::from(1));
}