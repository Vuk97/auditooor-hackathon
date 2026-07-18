use std::collections::HashSet;

pub struct Signature {
    pub signer: [u8; 32],
    pub bytes: Vec<u8>,
}

pub struct ValidationModule {
    pub signature_validation_enabled: bool,
}

pub struct UserOperation {
    pub sender: [u8; 32],
    pub nonce: u64,
    pub signature: Vec<u8>,
}

pub struct ClaimParams {
    pub account: [u8; 32],
    pub amount: u64,
    pub claim_id: [u8; 32],
}

pub struct ReplayGateway {
    pub chain_id: u64,
    pub entry_point: [u8; 32],
    pub signers: HashSet<[u8; 32]>,
    pub threshold: u32,
}

impl ReplayGateway {
    pub fn authorize_transfer(
        &self,
        signer: [u8; 32],
        amount: u64,
        signature: Vec<u8>,
    ) -> bool {
        let chain_id = self.chain_id;
        let entry_point = self.entry_point;
        let nonce = current_nonce(&signer);
        let mut payload = Vec::new();
        payload.extend_from_slice(&signer);
        payload.extend_from_slice(&amount.to_be_bytes());
        let digest = hash(&payload);
        verify_signature(&signer, &digest, &signature)
    }

    pub fn verify_execution(&self, signatures: &[Signature]) -> bool {
        let mut acquired_threshold = 0u32;
        for sig in signatures {
            if !self.signers.contains(&sig.signer) {
                continue;
            }
            if verify_sig(sig) {
                acquired_threshold += 1;
            }
            if acquired_threshold >= self.threshold {
                return true;
            }
        }
        false
    }

    pub fn validate_user_op(module: &ValidationModule, op: UserOperation) -> bool {
        if module.signature_validation_enabled {
            return validate_signature_path(&op.signature);
        }
        pre_validation_hook(&op);
        validate_user_op_signature(&op)
    }

    pub fn batch_claim(&self, claim_params: ClaimParams, merkle_proof: Vec<[u8; 32]>) {
        let params_hash = hash_claim(&claim_params);
        assert!(verify_proof(&merkle_proof, &params_hash), "bad proof");
        credit(&claim_params.account, claim_params.amount);
    }
}

fn current_nonce(_signer: &[u8; 32]) -> u64 { 7 }
fn hash(_payload: &[u8]) -> [u8; 32] { [0; 32] }
fn hash_claim(_params: &ClaimParams) -> [u8; 32] { [1; 32] }
fn verify_signature(_signer: &[u8; 32], _digest: &[u8; 32], _sig: &[u8]) -> bool { true }
fn verify_sig(_sig: &Signature) -> bool { true }
fn validate_signature_path(_sig: &[u8]) -> bool { true }
fn validate_user_op_signature(_op: &UserOperation) -> bool { true }
fn pre_validation_hook(_op: &UserOperation) {}
fn verify_proof(_proof: &Vec<[u8; 32]>, _params_hash: &[u8; 32]) -> bool { true }
fn credit(_account: &[u8; 32], _amount: u64) {}
