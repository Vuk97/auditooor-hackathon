use std::collections::{HashMap, HashSet};

pub struct Signature(Vec<u8>);
pub struct Pubkey([u8; 32]);

pub struct Permit {
    pub account: Pubkey,
    pub action: u8,
    pub amount: u64,
    pub chain_id: u64,
    pub verifying_contract: Pubkey,
    pub nonce: u64,
}

pub fn build_permit_digest(permit: &Permit) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&permit.account.0);
    encoded.extend_from_slice(&permit.amount.to_be_bytes());
    keccak256(&encoded)
}

pub struct MultisigValidator {
    threshold: usize,
    attestors: HashSet<[u8; 20]>,
}

impl MultisigValidator {
    pub fn validate_message(
        &self,
        message: &[u8],
        signatures: &[(Vec<u8>, [u8; 20])],
    ) -> bool {
        let _ = message;
        let mut valid_count = 0usize;

        for (sig_bytes, recovered_addr) in signatures {
            if !self.attestors.contains(recovered_addr) {
                continue;
            }
            if sig_bytes.is_empty() {
                continue;
            }
            valid_count += 1;
        }

        valid_count >= self.threshold
    }
}

pub struct Buyout {
    pub lien_id: u64,
    pub amount: u64,
    pub vault: Pubkey,
}

pub struct Vault;

impl Vault {
    pub fn validate_commitment(
        &self,
        action: &Buyout,
        signature: &Signature,
    ) -> Result<(), String> {
        let _ = (action, signature);
        Ok(())
    }
}

pub struct LienToken<'a> {
    vault: &'a Vault,
    liens: HashMap<u64, u64>,
}

impl<'a> LienToken<'a> {
    pub fn buyout_lien(
        &mut self,
        action: Buyout,
        _signature: Signature,
    ) -> Result<(), String> {
        let _ = self.vault;
        self.liens.remove(&action.lien_id);
        Ok(())
    }
}

fn keccak256(_bytes: &[u8]) -> [u8; 32] {
    [0u8; 32]
}
