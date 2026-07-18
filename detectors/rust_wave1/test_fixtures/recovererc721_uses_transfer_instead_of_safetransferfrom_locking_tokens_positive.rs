use std::marker::PhantomData;

// Mock ERC721 interface - note missing safe_transfer_from usage
pub trait IERC721 {
    fn safe_transfer_from(&mut self, from: Address, to: Address, token_id: U256);
    fn transfer(&mut self, to: Address, token_id: U256); // non-standard, unsafe
    fn transfer_from(&mut self, from: Address, to: Address, token_id: U256);
}

use alloy_primitives::{Address, U256};

pub struct TokenRecovery<T: IERC721> {
    token: T,
}

pub struct MockERC721;

impl IERC721 for MockERC721 {
    fn safe_transfer_from(&mut self, from: Address, to: Address, token_id: U256) {
        let _ = (from, to, token_id);
    }
    
    fn transfer(&mut self, to: Address, token_id: U256) {
        // UNSAFE: No receiver check - can lock tokens in contracts
        let _ = (to, token_id);
    }
    
    fn transfer_from(&mut self, from: Address, to: Address, token_id: U256) {
        let _ = (from, to, token_id);
    }
}

impl<T: IERC721> TokenRecovery<T> {
    pub fn new(token: T) -> Self {
        Self { token }
    }
    
    /// Recover ERC721 tokens - BUG: uses transfer instead of safeTransferFrom
    pub fn recover_erc721(&mut self, to: Address, token_id: U256) {
        // VULNERABLE: Uses transfer (or transfer_from) instead of safe_transfer_from
        // This can permanently lock tokens in contracts that don't implement
        // onERC721Received, as there's no check if the receiver can handle ERC721
        self.token.transfer(to, token_id);
    }
}

fn main() {
    let token = MockERC721;
    let mut recovery = TokenRecovery::new(token);
    recovery.recover_erc721(Address::ZERO, U256::from(1));
}