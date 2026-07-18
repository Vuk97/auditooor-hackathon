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
    encoded.extend_from_slice(&permit.action.to_be_bytes());
    encoded.extend_from_slice(&permit.amount.to_be_bytes());
    encoded.extend_from_slice(&permit.chain_id.to_be_bytes());
    encoded.extend_from_slice(&permit.verifying_contract.0);
    encoded.extend_from_slice(&permit.nonce.to_be_bytes());
    keccak256(&encoded)
}

pub fn hash_ids_and_amounts(ids_and_amounts: &[(u128, u128)]) -> [u8; 32] {
    let element_hashes: Vec<u8> = ids_and_amounts
        .iter()
        .flat_map(|(a, b)| {
            let mut encoded = [0u8; 32];
            encoded[0..16].copy_from_slice(&a.to_be_bytes());
            encoded[16..32].copy_from_slice(&b.to_be_bytes());
            keccak256(&encoded).to_vec()
        })
        .collect();
    keccak256(&element_hashes)
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
        let mut seen_signers: HashSet<[u8; 20]> = HashSet::new();
        let mut valid_count = 0usize;

        for (sig_bytes, recovered_addr) in signatures {
            if !seen_signers.insert(*recovered_addr) {
                continue;
            }
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
        signature: Signature,
    ) -> Result<(), String> {
        self.vault.validate_commitment(&action, &signature)?;
        self.liens.remove(&action.lien_id);
        Ok(())
    }
}

fn keccak256(_bytes: &[u8]) -> [u8; 32] {
    [0u8; 32]
}
