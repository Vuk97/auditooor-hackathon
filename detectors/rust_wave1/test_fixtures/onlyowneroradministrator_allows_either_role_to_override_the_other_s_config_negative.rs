use std::collections::HashMap;

pub struct ConfigManager {
    owner: [u8; 32],
    administrator: [u8; 32],
    allowlist: Vec<[u8; 32]>,
    signer: [u8; 32],
    base_uri: String,
    // Separate ownership tracking for critical operations
    owner_only_configs: HashMap<String, bool>,
}

pub enum AuthError {
    Unauthorized,
}

impl ConfigManager {
    pub fn new(owner: [u8; 32], administrator: [u8; 32]) -> Self {
        let mut owner_only_configs = HashMap::new();
        owner_only_configs.insert("allowlist".to_string(), true);
        owner_only_configs.insert("signer".to_string(), true);
        owner_only_configs.insert("base_uri".to_string(), true);
        
        Self {
            owner,
            administrator,
            allowlist: Vec::new(),
            signer: [0u8; 32],
            base_uri: String::new(),
            owner_only_configs,
        }
    }

    fn require_owner(&self, caller: [u8; 32]) -> Result<(), AuthError> {
        if caller != self.owner {
            return Err(AuthError::Unauthorized);
        }
        Ok(())
    }

    fn require_administrator(&self, caller: [u8; 32]) -> Result<(), AuthError> {
        if caller != self.administrator {
            return Err(AuthError::Unauthorized);
        }
        Ok(())
    }

    // Owner-only: critical config that owner should exclusively control
    pub fn set_allowlist(&mut self, caller: [u8; 32], allowlist: Vec<[u8; 32]>) -> Result<(), AuthError> {
        self.require_owner(caller)?;
        self.allowlist = allowlist;
        Ok(())
    }

    // Owner-only: critical config that owner should exclusively control
    pub fn set_signer(&mut self, caller: [u8; 32], signer: [u8; 32]) -> Result<(), AuthError> {
        self.require_owner(caller)?;
        self.signer = signer;
        Ok(())
    }

    // Owner-only: critical config that owner should exclusively control
    pub fn set_base_uri(&mut self, caller: [u8; 32], uri: String) -> Result<(), AuthError> {
        self.require_owner(caller)?;
        self.base_uri = uri;
        Ok(())
    }

    // Administrator-only: operational config that admin should exclusively control
    pub fn set_operational_param(&mut self, caller: [u8; 32], param: u64) -> Result<(), AuthError> {
        self.require_administrator(caller)?;
        // Operational parameters that don't override owner config
        let _ = param;
        Ok(())
    }

    // Explicit dual-auth for emergency: requires BOTH parties
    pub fn emergency_update(&mut self, owner_sig: [u8; 32], admin_sig: [u8; 32]) -> Result<(), AuthError> {
        self.require_owner(owner_sig)?;
        self.require_administrator(admin_sig)?;
        // Both must agree
        Ok(())
    }
}

fn main() {
    let owner = [1u8; 32];
    let admin = [2u8; 32];
    let mut cm = ConfigManager::new(owner, admin);
    
    // Owner can set allowlist
    cm.set_allowlist(owner, vec![[3u8; 32]]).unwrap();
    
    // Admin CANNOT override owner's allowlist
    assert!(cm.set_allowlist(admin, vec![[4u8; 32]]).is_err());
}