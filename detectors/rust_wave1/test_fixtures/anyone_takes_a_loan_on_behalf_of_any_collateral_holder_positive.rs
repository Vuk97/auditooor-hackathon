use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address([u8; 32]);

#[derive(Clone, Debug)]
pub struct LoanCommitment {
    pub collateral_owner: Address,
    pub borrower: Address,
    pub collateral_id: u64,
    pub loan_amount: u64,
    pub terms_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub signer: Address,
    pub data: [u8; 64],
}

pub struct Vault {
    pub loans: HashMap<u64, LoanCommitment>,
    pub collateral_locked: HashMap<u64, bool>,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            loans: HashMap::new(),
            collateral_locked: HashMap::new(),
        }
    }

    pub fn take_loan(
        &mut self,
        commitment: LoanCommitment,
        signature: Signature,
        caller: Address,
    ) -> Result<(), &'static str> {
        // BUG: Only validates caller OR receiver is authorized, not that caller IS owner
        self._validate_commitment(&commitment, &signature, &caller)?;

        if self.collateral_locked.contains_key(&commitment.collateral_id) {
            return Err("collateral already locked");
        }

        self.collateral_locked.insert(commitment.collateral_id, true);
        self.loans.insert(commitment.collateral_id, commitment);
        Ok(())
    }

    fn _validate_commitment(
        &self,
        commitment: &LoanCommitment,
        signature: &Signature,
        caller: &Address,
    ) -> Result<(), &'static str> {
        // VULNERABLE: Checks caller == borrower OR valid signature from owner
        // Attacker can set borrower = attacker, pass signature check via precomputed hash
        let is_authorized = *caller == commitment.borrower || signature.signer == commitment.collateral_owner;
        
        if !is_authorized {
            return Err("unauthorized");
        }
        
        // BUG: Missing check that caller == collateral_owner
        // Attacker can use victim's NFT as collateral with attacker-favorable terms
        Ok(())
    }
}

fn main() {
    let mut vault = Vault::new();
    let victim = Address([1u8; 32]);
    let attacker = Address([2u8; 32]);

    // Attacker constructs commitment with victim's collateral but attacker as borrower
    let commitment = LoanCommitment {
        collateral_owner: victim.clone(),
        borrower: attacker.clone(), // attacker sets self as borrower
        collateral_id: 1,
        loan_amount: 1000,
        terms_hash: [0u8; 32],
    };

    // Precomputed or replayed signature from victim (e.g., from different context)
    let signature = Signature {
        signer: victim.clone(), // valid signature from victim, but for different terms
        data: [0u8; 64],
    };

    // EXPLOIT: Attacker takes loan against victim's collateral
    // _validate_commitment passes because caller == borrower check succeeds
    // even though caller != collateral_owner
    let result = vault.take_loan(commitment, signature, attacker);
    assert!(result.is_ok()); // BUG: should have failed
}