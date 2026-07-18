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

    pub fn safe_mint(
        &mut self,
        to: Address,
        token_id: u256,
        data: Vec<u8>,
    ) -> Result<(), TokenReceiverError> {
        self.mint(to.clone(), token_id)?;
        
        if self.is_contract(&to) {
            let selector = self.call_on_erc721_received(
                Address([0u8; 20]),
                Address([0u8; 20]),
                to.clone(),
                token_id,
                data,
            )?;
            let expected = [0x15, 0x0b, 0x7a, 0x02];
            if selector != expected {
                return Err(TokenReceiverError::TransferRejected);
            }
        }
        Ok(())
    }

    pub fn safe_transfer_from(
        &mut self,
        from: Address,
        to: Address,
        token_id: u256,
        data: Vec<u8>,
    ) -> Result<(), TokenReceiverError> {
        self.transfer(from.clone(), to.clone(), token_id)?;
        
        if self.is_contract(&to) {
            let selector = self.call_on_erc721_received(
                Address([0u8; 20]),
                from,
                to.clone(),
                token_id,
                data,
            )?;
            let expected = [0x15, 0x0b, 0x7a, 0x02];
            if selector != expected {
                return Err(TokenReceiverError::TransferRejected);
            }
        }
        Ok(())
    }

    fn mint(&mut self, to: Address, token_id: u256) -> Result<(), TokenReceiverError> {
        self.owners.insert(token_id, to.clone());
        let balance = self.balances.get(&to).copied().unwrap_or(u256::ZERO);
        self.balances.insert(to, balance + u256::from(1u64));
        Ok(())
    }

    fn transfer(
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

    fn is_contract(&self, _addr: &Address) -> bool {
        false
    }

    fn call_on_erc721_received(
        &self,
        _operator: Address,
        _from: Address,
        _to: Address,
        _token_id: u256,
        _data: Vec<u8>,
    ) -> Result<[u8; 4], TokenReceiverError> {
        Ok([0x15, 0x0b, 0x7a, 0x02])
    }
}

use alloy_primitives::U256 as u256;