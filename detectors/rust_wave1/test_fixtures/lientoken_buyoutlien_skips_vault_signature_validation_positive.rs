use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct LienActionBuyout {
    pub lien_id: u64,
    pub amount: u64,
    pub vault: Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Pubkey([u8; 32]);

pub struct Signature([u8; 64]);

pub struct LienToken<'a> {
    vault_impl: &'a VaultImplementation,
    liens: HashMap<u64, Lien>,
}

pub struct Lien {
    pub owner: Pubkey,
    pub amount: u64,
}

pub struct VaultImplementation;

impl VaultImplementation {
    pub fn _validate_commitment(
        &self,
        action: &LienActionBuyout,
        signature: &Signature,
    ) -> Result<(), String> {
        // Verify vault signature on the commitment
        if signature.0[0] == 0 {
            return Err("Invalid signature".to_string());
        }
        Ok(())
    }

    pub fn buyout_lien(
        &self,
        action: LienActionBuyout,
        signature: Signature,
    ) -> Result<(), String> {
        // Vault path validates signature
        self._validate_commitment(&action, &signature)?;
        // Proceed with buyout via LienToken
        Ok(())
    }
}

impl<'a> LienToken<'a> {
    pub fn new(vault_impl: &'a VaultImplementation) -> Self {
        Self {
            vault_impl,
            liens: HashMap::new(),
        }
    }

    /// VULNERABLE: Direct call skips vault signature validation
    /// Attacker can call this directly, bypassing VaultImplementation.buyout_lien
    pub fn buyout_lien(
        &mut self,
        action: LienActionBuyout,
        _signature: Signature,
    ) -> Result<(), String> {
        // BUG: Missing _validate_commitment call!
        // The vault signature is never verified on this direct path
        
        let lien = self.liens.get(&action.lien_id)
            .ok_or("Lien not found")?;
        
        if lien.amount > action.amount {
            return Err("Insufficient amount".to_string());
        }
        
        self.liens.remove(&action.lien_id);
        Ok(())
    }

    pub fn insert_lien(&mut self, id: u64, lien: Lien) {
        self.liens.insert(id, lien);
    }
}

fn main() {
    let vault = VaultImplementation;
    let mut lien_token = LienToken::new(&vault);
    
    let action = LienActionBuyout {
        lien_id: 1,
        amount: 100,
        vault: Pubkey([0u8; 32]),
    };
    let sig = Signature([1u8; 64]);
    
    // Direct call bypasses vault signature check!
    let _ = lien_token.buyout_lien(action, sig);
}