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
    pub used_claims: HashSet<[u8; 32]>,
}

impl ReplayGateway {
    pub fn authorize_transfer(
        &mut self,
        signer: [u8; 32],
        amount: u64,
        signature: Vec<u8>,
    ) -> bool {
        let chain_id = self.chain_id;
        let entry_point = self.entry_point;
        let nonce = current_nonce(&signer);
        let action = b"authorize_transfer";
        let mut payload = Vec::new();
        payload.extend_from_slice(&chain_id.to_be_bytes());
        payload.extend_from_slice(&entry_point);
        payload.extend_from_slice(&nonce.to_be_bytes());
        payload.extend_from_slice(action);
        payload.extend_from_slice(&signer);
        payload.extend_from_slice(&amount.to_be_bytes());
        let digest = hash(&payload);
        let ok = verify_signature(&signer, &digest, &signature);
        if ok {
            consume_nonce(&signer, nonce);
        }
        ok
    }

    pub fn verify_execution(&self, signatures: &[Signature]) -> bool {
        let mut acquired_threshold = 0u32;
        let mut seen_signers = HashSet::new();
        for sig in signatures {
            if !self.signers.contains(&sig.signer) {
                continue;
            }
            if !seen_signers.insert(sig.signer) {
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
            pre_validation_hook(&op);
            return validate_signature_path(&op.signature);
        }
        pre_validation_hook(&op);
        validate_user_op_signature(&op)
    }

    pub fn batch_claim(&mut self, claim_params: ClaimParams, merkle_proof: Vec<[u8; 32]>) {
        let params_hash = hash_claim(&claim_params);
        assert!(verify_proof(&merkle_proof, &params_hash), "bad proof");
        assert!(!self.used_claims.contains(&params_hash), "already claimed");
        self.used_claims.insert(params_hash);
        credit(&claim_params.account, claim_params.amount);
    }
}

fn current_nonce(_signer: &[u8; 32]) -> u64 { 7 }
fn consume_nonce(_signer: &[u8; 32], _nonce: u64) {}
fn hash(_payload: &[u8]) -> [u8; 32] { [0; 32] }
fn hash_claim(_params: &ClaimParams) -> [u8; 32] { [1; 32] }
fn verify_signature(_signer: &[u8; 32], _digest: &[u8; 32], _sig: &[u8]) -> bool { true }
fn verify_sig(_sig: &Signature) -> bool { true }
fn validate_signature_path(_sig: &[u8]) -> bool { true }
fn validate_user_op_signature(_op: &UserOperation) -> bool { true }
fn pre_validation_hook(_op: &UserOperation) {}
fn verify_proof(_proof: &Vec<[u8; 32]>, _params_hash: &[u8; 32]) -> bool { true }
fn credit(_account: &[u8; 32], _amount: u64) {}
