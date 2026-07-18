use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Address(u64);

const ERC721_RECEIVED: [u8; 4] = [0x15, 0x0b, 0x7a, 0x02];

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
    fn release_with_hook(
        &mut self,
        token_id: u64,
        receiver: u64,
        caller: u64,
    ) -> Result<(), &'static str> {
        let owner = *self.owner_of.get(&token_id).ok_or("missing owner")?;
        if caller != owner {
            return Err("not owner");
        }

        self.pending_release.insert(token_id);
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

    pub fn safe_mint<R: Erc721Receiver>(
        &mut self,
        to: Address,
        token_id: u64,
        receiver: &mut R,
    ) -> Result<(), TokenReceiverError> {
        self.mint(to.clone(), token_id)?;
        let magic = receiver.on_erc721_received(to.clone(), to, token_id)?;
        if magic != ERC721_RECEIVED {
            return Err(TokenReceiverError::TransferRejected);
        }
        Ok(())
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
        let old_owner = sr.owner;
        sr.owner = new_owner;
        self.owner_to_record.remove(&old_owner);
        self.owner_to_record.insert(new_owner, record_id);
        Ok(())
    }

    fn burn(&mut self, caller: u64, record_id: u64) -> Result<(), &'static str> {
        let current_owner = self.records.get(&record_id).ok_or("not found")?.owner;
        if current_owner != caller {
            return Err("not owner");
        }
        self.owner_to_record.remove(&caller);
        self.records.remove(&record_id);
        Ok(())
    }
}
