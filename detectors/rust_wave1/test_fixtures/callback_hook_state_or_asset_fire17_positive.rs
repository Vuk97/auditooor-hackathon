use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Address(u64);

pub enum TokenReceiverError {
    TransferRejected,
    InvalidRecipient,
}

pub trait Erc721Receiver {
    fn on_erc721_received(
        &mut self,
        operator: Address,
        from: Address,
        token_id: u64,
    ) -> Result<[u8; 4], TokenReceiverError>;
}

struct ReleaseHook;

impl ReleaseHook {
    fn before_release(&self, _token_id: u64) -> Result<(), &'static str> {
        Ok(())
    }
}

struct Vault {
    owner_of: HashMap<u64, u64>,
    escrow: HashMap<u64, u128>,
    pending_release: HashSet<u64>,
    release_hook: ReleaseHook,
}

impl Vault {
    fn release_with_hook(&mut self, token_id: u64, receiver: u64) -> Result<(), &'static str> {
        self.release_hook.before_release(token_id)?;

        let _locked_value = self.escrow.remove(&token_id).ok_or("missing escrow")?;
        self.owner_of.insert(token_id, receiver);
        self.pending_release.remove(&token_id);

        Ok(())
    }
}

pub struct Erc721Token {
    balances: HashMap<Address, u64>,
    owners: HashMap<u64, Address>,
}

impl Erc721Token {
    pub fn mint(&mut self, to: Address, token_id: u64) -> Result<(), TokenReceiverError> {
        self.owners.insert(token_id, to.clone());
        let balance = self.balances.get(&to).copied().unwrap_or(0);
        self.balances.insert(to, balance + 1);
        Ok(())
    }

    pub fn transfer_from(
        &mut self,
        from: Address,
        to: Address,
        token_id: u64,
    ) -> Result<(), TokenReceiverError> {
        let owner = self.owners.get(&token_id).ok_or(TokenReceiverError::InvalidRecipient)?;
        if *owner != from {
            return Err(TokenReceiverError::InvalidRecipient);
        }
        self.owners.insert(token_id, to.clone());
        Ok(())
    }

    pub fn safe_mint(
        &mut self,
        to: Address,
        token_id: u64,
    ) -> Result<(), TokenReceiverError> {
        self.mint(to, token_id)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ShortRecord {
    owner: u64,
    data: u128,
}

struct Registry {
    records: HashMap<u64, ShortRecord>,
    owner_to_record: HashMap<u64, u64>,
}

impl Registry {
    fn transfer(&mut self, record_id: u64, new_owner: u64) -> Result<(), &'static str> {
        let sr = self.records.get_mut(&record_id).ok_or("not found")?;
        sr.owner = new_owner;
        Ok(())
    }

    fn burn(&mut self, caller: u64, record_id: u64) -> Result<(), &'static str> {
        let mapped_record = self.owner_to_record.get(&caller);
        if mapped_record != Some(&record_id) {
            return Err("not owner");
        }
        self.records.remove(&record_id);
        Ok(())
    }
}
