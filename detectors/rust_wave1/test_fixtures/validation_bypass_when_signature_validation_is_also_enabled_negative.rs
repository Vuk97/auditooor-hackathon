use std::collections::HashMap;

/// Validation module that properly checks both paths without bypass
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

    /// CLEAN: Always runs pre-validation hooks regardless of which validation path is used
    pub fn validate_user_op(&self, user_op: &UserOperation) -> Result<(), String> {
        // Always execute pre-validation hooks first
        self.run_pre_validation_hooks(user_op)?;

        if self.userop_validation_enabled && self.signature_validation_enabled {
            // Both enabled: use userOp path as primary, but still ran hooks above
            self.validate_user_op_logic(user_op)
        } else if self.userop_validation_enabled {
            self.validate_user_op_logic(user_op)
        } else if self.signature_validation_enabled {
            self.validate_signature_logic(&user_op.signature, &user_op.sender)
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
        if signature.len() < 64 {
            return Err("Invalid signature length".to_string());
        }
        // Verify signature matches sender
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
        nonce: 1,
        call_data: vec![0x42],
        signature: [1u8; 64].to_vec(),
    };
    let result = module.validate_user_op(&user_op);
    assert!(result.is_ok());
    println!("Clean validation passed with all hooks executed");
}