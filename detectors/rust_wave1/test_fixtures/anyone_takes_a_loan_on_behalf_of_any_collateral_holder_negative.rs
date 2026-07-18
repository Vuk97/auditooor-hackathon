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
        // FIXED: Must verify caller IS the collateral owner, not just authorized
        if caller != commitment.collateral_owner {
            return Err("caller must be collateral owner");
        }

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
        // Verify signature is from collateral owner
        if signature.signer != commitment.collateral_owner {
            return Err("invalid signature");
        }
        // Signature data validation would happen here
        let _ = caller; // caller already verified in take_loan
        Ok(())
    }
}

fn main() {
    let mut vault = Vault::new();
    let owner = Address([1u8; 32]);
    let attacker = Address([2u8; 32]);

    let commitment = LoanCommitment {
        collateral_owner: owner.clone(),
        borrower: attacker.clone(),
        collateral_id: 1,
        loan_amount: 1000,
        terms_hash: [0u8; 32],
    };

    let signature = Signature {
        signer: owner.clone(),
        data: [0u8; 64],
    };

    // Attacker cannot take loan on behalf of owner
    let result = vault.take_loan(commitment, signature, attacker);
    assert!(result.is_err());

    // Owner can take their own loan
    let commitment2 = LoanCommitment {
        collateral_owner: owner.clone(),
        borrower: owner.clone(),
        collateral_id: 2,
        loan_amount: 1000,
        terms_hash: [0u8; 32],
    };
    let signature2 = Signature {
        signer: owner.clone(),
        data: [0u8; 64],
    };
    let result = vault.take_loan(commitment2, signature2, owner);
    assert!(result.is_ok());
}