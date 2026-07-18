use std::collections::HashMap;

pub struct ConfigManager {
    owner: [u8; 32],
    administrator: [u8; 32],
    allowlist: Vec<[u8; 32]>,
    signer: [u8; 32],
    base_uri: String,
}

pub enum AuthError {
    Unauthorized,
}

impl ConfigManager {
    pub fn new(owner: [u8; 32], administrator: [u8; 32]) -> Self {
        Self {
            owner,
            administrator,
            allowlist: Vec::new(),
            signer: [0u8; 32],
            base_uri: String::new(),
        }
    }

    // BUG: This modifier allows EITHER owner OR administrator
    // Either role can override the other's configuration
    fn only_owner_or_administrator(&self, caller: [u8; 32]) -> Result<(), AuthError> {
        if caller != self.owner && caller != self.administrator {
            return Err(AuthError::Unauthorized);
        }
        Ok(())
    }

    // VULNERABLE: Admin can override owner-set allowlist without owner consent
    pub fn set_allowlist(&mut self, caller: [u8; 32], allowlist: Vec<[u8; 32]>) -> Result<(), AuthError> {
        self.only_owner_or_administrator(caller)?;
        self.allowlist = allowlist;
        Ok(())
    }

    // VULNERABLE: Admin can override owner-set signer without owner consent
    pub fn set_signer(&mut self, caller: [u8; 32], signer: [u8; 32]) -> Result<(), AuthError> {
        self.only_owner_or_administrator(caller)?;
        self.signer = signer;
        Ok(())
    }

    // VULNERABLE: Admin can override owner-set URI without owner consent
    pub fn set_base_uri(&mut self, caller: [u8; 32], uri: String) -> Result<(), AuthError> {
        self.only_owner_or_administrator(caller)?;
        self.base_uri = uri;
        Ok(())
    }

    // VULNERABLE: Owner can override admin-set operational params too
    pub fn set_operational_param(&mut self, caller: [u8; 32], param: u64) -> Result<(), AuthError> {
        self.only_owner_or_administrator(caller)?;
        let _ = param;
        Ok(())
    }
}

fn main() {
    let owner = [1u8; 32];
    let admin = [2u8; 32];
    let mut cm = ConfigManager::new(owner, admin);
    
    // Owner sets allowlist
    cm.set_allowlist(owner, vec![[3u8; 32]]).unwrap();
    
    // BUG: Admin can override without owner consent!
    cm.set_allowlist(admin, vec![[4u8; 32]]).unwrap();
    
    // Owner can also override admin decisions
    cm.set_operational_param(owner, 42).unwrap();
}