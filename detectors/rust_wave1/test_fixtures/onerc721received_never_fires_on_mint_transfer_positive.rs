use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
pub struct Address([u8; 20]);

pub enum TokenReceiverError {
    TransferRejected,
    InvalidRecipient,
}

pub trait IERC721Receiver {
    fn on_erc721_received(
        &mut self,
        operator: Address,
        from: Address,
        token_id: u256,
        data: Vec<u8>,
    ) -> Result<[u8; 4], TokenReceiverError>;
}

pub struct ERC721Token {
    balances: HashMap<Address, u256>,
    owners: HashMap<u256, Address>,
}

impl ERC721Token {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            owners: HashMap::new(),
        }
    }

    pub fn mint(
        &mut self,
        to: Address,
        token_id: u256,
    ) -> Result<(), TokenReceiverError> {
        self.owners.insert(token_id, to.clone());
        let balance = self.balances.get(&to).copied().unwrap_or(u256::ZERO);
        self.balances.insert(to, balance + u256::from(1u64));
        Ok(())
    }

    pub fn transfer_from(
        &mut self,
        from: Address,
        to: Address,
        token_id: u256,
    ) -> Result<(), TokenReceiverError> {
        let owner = self.owners.get(&token_id).ok_or(TokenReceiverError::InvalidRecipient)?;
        if *owner != from {
            return Err(TokenReceiverError::InvalidRecipient);
        }
        self.owners.insert(token_id, to.clone());
        let from_bal = self.balances.get(&from).copied().unwrap_or(u256::ZERO);
        self.balances.insert(from, from_bal - u256::from(1u64));
        let to_bal = self.balances.get(&to).copied().unwrap_or(u256::ZERO);
        self.balances.insert(to, to_bal + u256::from(1u64));
        Ok(())
    }

    pub fn safe_mint(
        &mut self,
        to: Address,
        token_id: u256,
    ) -> Result<(), TokenReceiverError> {
        self.mint(to, token_id)
    }

    pub fn safe_transfer_from(
        &mut self,
        from: Address,
        to: Address,
        token_id: u256,
    ) -> Result<(), TokenReceiverError> {
        self.transfer_from(from, to, token_id)
    }
}

use alloy_primitives::U256 as u256;