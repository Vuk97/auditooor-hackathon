use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct BoundAccounts<'info> {
    // OK: account identity is bound by seeds and authority.
    #[account(seeds = [b"pool", authority.key().as_ref()], bump)]
    pub pool_config: Account<'info, PoolConfig>,

    // OK: account identity is tied to authority.
    #[account(has_one = authority)]
    pub claimant_state: Account<'info, ClaimantState>,

    pub authority: Signer<'info>,
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

        assert_eq!(total_distributed_amount, self.public_input_total);
        constrain(total_distributed_amount == self.public_input_total);
    }

    pub fn assign_range_constraint(&self, amount: u64, max_amount: u64) {
        assert!(amount <= max_amount);
    }
}

pub struct RecursiveVerifier;

impl RecursiveVerifier {
    pub fn verify_recursive_proof(mut transcript: Transcript, proof_openings: Vec<u128>) -> bool {
        for opening in proof_openings {
            transcript.observe(opening);
        }
        let alpha = transcript.challenge();
        alpha != 0
    }
}

pub type Pubkey = [u8; 32];

pub fn verify_admin_signature(
    expected_signer: Pubkey,
    message_hash: [u8; 32],
    signature: [u8; 64],
) -> bool {
    let recovered_signer = recover_signer(message_hash, signature);
    require_keys_eq!(recovered_signer, expected_signer);
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
