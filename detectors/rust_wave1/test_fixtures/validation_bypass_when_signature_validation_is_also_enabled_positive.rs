use std::collections::HashMap;

/// Validation module with bypass bug: signature path skips pre-validation hooks
pub struct ValidationModule {
    pub userop_validation_enabled: bool,
    pub signature_validation_enabled: bool,
    pub pre_validation_hooks: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct UserOperation {
    pub sender: [u8; 32],
    pub nonce: u64,
    pub call_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ValidationModule {
    pub fn new() -> Self {
        Self {
            userop_validation_enabled: true,
            signature_validation_enabled: true,
            pre_validation_hooks: vec!["check_gas".to_string(), "check_paymaster".to_string()],
        }
    }

    /// VULNERABLE: When both enabled, signature path replaces userOp path and SKIPS hooks
    pub fn validate_user_op(&self, user_op: &UserOperation) -> Result<(), String> {
        // BUG: Pre-validation hooks only run on userOp path, but when both
        // validations are enabled, we fall through to signature path which
        // bypasses all pre-validation hooks entirely
        if self.userop_validation_enabled && !self.signature_validation_enabled {
            // Only userOp validation: run hooks and validate
            self.run_pre_validation_hooks(user_op)?;
            self.validate_user_op_logic(user_op)
        } else if self.signature_validation_enabled {
            // BUG: This path is taken when BOTH are enabled, skipping hooks!
            // The userOp flow is replaced by signature-validation fallback
            self.validate_signature_logic(&user_op.signature, &user_op.sender)
        } else if self.userop_validation_enabled {
            self.run_pre_validation_hooks(user_op)?;
            self.validate_user_op_logic(user_op)
        } else {
            Err("No validation enabled".to_string())
        }
    }

    fn run_pre_validation_hooks(&self, _user_op: &UserOperation) -> Result<(), String> {
        for hook in &self.pre_validation_hooks {
            println!("Running pre-validation hook: {}", hook);
        }
        Ok(())
    }

    fn validate_user_op_logic(&self, user_op: &UserOperation) -> Result<(), String> {
        if user_op.nonce == 0 {
            return Err("Invalid nonce".to_string());
        }
        Ok(())
    }

    fn validate_signature_logic(&self, signature: &[u8], sender: &[u8; 32]) -> Result<(), String> {
        // No pre-validation hooks called here!
        if signature.len() < 64 {
            return Err("Invalid signature length".to_string());
        }
        if signature[0..32] != sender[..] {
            return Err("Signature mismatch".to_string());
        }
        Ok(())
    }
}

fn main() {
    let module = ValidationModule::new();
    let user_op = UserOperation {
        sender: [1u8; 32],
        nonce: 0, // Invalid nonce that should be caught by pre-validation hooks
        call_data: vec![0x42],
        signature: [1u8; 64].to_vec(),
    };
    // BUG: This succeeds even with nonce=0 because hooks are skipped!
    let result = module.validate_user_op(&user_op);
    assert!(result.is_ok());
    println!("Vulnerable: bypassed pre-validation hooks via signature path");
}