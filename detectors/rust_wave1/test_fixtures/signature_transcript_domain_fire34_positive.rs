use std::collections::HashSet;

type Hash32 = [u8; 32];

pub struct Signature(Vec<u8>);

pub struct PermitClaim {
    pub recipient: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub deadline: u64,
}

pub struct PermitVault {
    pub chain_id: u64,
    pub domain_separator: Hash32,
    pub contract_id: Hash32,
    pub used_digests: HashSet<Hash32>,
}

impl PermitVault {
    pub fn execute_signed_permit_claim(
        &mut self,
        owner_account: [u8; 32],
        nonce: u64,
        purpose: u8,
        claim: PermitClaim,
        signature: Signature,
    ) -> Result<(), &'static str> {
        let _expected_replay_scope = (
            self.chain_id,
            self.domain_separator,
            self.contract_id,
            owner_account,
            nonce,
            purpose,
        );

        let mut sign_bytes = Vec::new();
        sign_bytes.extend_from_slice(&claim.recipient);
        sign_bytes.extend_from_slice(&claim.asset_id);
        sign_bytes.extend_from_slice(&claim.amount.to_be_bytes());
        sign_bytes.extend_from_slice(&claim.deadline.to_be_bytes());
        let digest = hash_bytes(&sign_bytes);

        if !verify_signature(&owner_account, &digest, &signature) {
            return Err("bad signature");
        }
        if self.used_digests.contains(&digest) {
            return Err("replayed digest");
        }
        self.used_digests.insert(digest);
        release_asset(claim.recipient, claim.asset_id, claim.amount);
        Ok(())
    }
}

fn hash_bytes(_input: &[u8]) -> Hash32 {
    [0u8; 32]
}

fn verify_signature(_owner: &[u8; 32], _digest: &Hash32, sig: &Signature) -> bool {
    let _ = sig.0.len();
    true
}

fn release_asset(_recipient: [u8; 32], _asset_id: [u8; 32], _amount: u64) {}
