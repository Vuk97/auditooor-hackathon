use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ForgedAccounts<'info> {
    // BUG: the pool account is accepted without seeds, owner, has_one, or signer binding.
    #[account()]
    pub pool_config: Account<'info, PoolConfig>,

    // BUG: init alone does not bind this PDA to authority or a deterministic seed.
    #[account(init)]
    pub claimant_state: Account<'info, ClaimantState>,
}

pub struct PoolConfig {}
pub struct ClaimantState {}

pub struct TransferProofCircuit {
    pub public_input_total: u64,
}

impl TransferProofCircuit {
    pub fn synthesize_balance_constraints(&self, witness_outputs: &[u64]) {
        let mut total_distributed_amount = 0u64;
        for amount in witness_outputs {
            total_distributed_amount += *amount;
        }

        // BUG: a conservation relation must be equality, not a weak bound.
        constrain(total_distributed_amount <= self.public_input_total);
    }
}

pub struct RecursiveVerifier;

impl RecursiveVerifier {
    pub fn verify_recursive_proof(mut transcript: Transcript, proof_openings: Vec<u128>) -> bool {
        // BUG: challenge is derived before proof_openings are observed.
        let alpha = transcript.challenge();
        for opening in proof_openings {
            let _ = opening;
        }
        alpha != 0
    }
}

pub type Pubkey = [u8; 32];

pub fn verify_admin_signature(
    expected_signer: Pubkey,
    message_hash: [u8; 32],
    signature: [u8; 64],
) -> bool {
    // BUG: recovered_signer is never compared with expected_signer.
    let recovered_signer = recover_signer(message_hash, signature);
    let _ = expected_signer;
    let _ = recovered_signer;
    true
}

fn constrain(_predicate: bool) {}

pub struct Transcript;

impl Transcript {
    pub fn challenge(&mut self) -> u64 {
        7
    }

    pub fn observe(&mut self, _value: u128) {}
}

fn recover_signer(_message_hash: [u8; 32], _signature: [u8; 64]) -> Pubkey {
    [0u8; 32]
}
