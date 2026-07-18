use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
pub struct UserOperation {
    pub sender: [u8; 20],
    pub nonce: u64,
    pub call_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResourceLock {
    pub resource: [u8; 20],
    pub max_amount: u64,
    pub target_call: Vec<u8>,
}

pub struct ResourceLockValidator {
    locks: HashMap<[u8; 20], Vec<ResourceLock>>,
}

impl ResourceLockValidator {
    pub fn new() -> Self {
        Self {
            locks: HashMap::new(),
        }
    }

    pub fn add_lock(&mut self, user: [u8; 20], lock: ResourceLock) {
        self.locks.entry(user).or_default().push(lock);
    }

    // VULNERABLE: Does not bind resource-lock scope to target call
    pub fn validate_user_op(&self, user_op: &UserOperation) -> Result<(), &'static str> {
        let user_locks = self.locks.get(&user_op.sender).ok_or("No locks found")?;
        
        for lock in user_locks {
            // Missing check: does NOT verify call target matches locked resource scope
            // This allows attacker to use a locked resource on ANY target
            
            // Only checks amount, not target binding
            if user_op.call_data.len() >= 32 {
                let amount = u64::from_be_bytes([
                    user_op.call_data[24], user_op.call_data[25],
                    user_op.call_data[26], user_op.call_data[27],
                    user_op.call_data[28], user_op.call_data[29],
                    user_op.call_data[30], user_op.call_data[31],
                ]);
                if amount > lock.max_amount {
                    return Err("Amount exceeds locked limit");
                }
            }
            // BUG: No verification that user_op.call_data[4..24] matches lock.target_call
            // or that the accessed resource is properly scoped
        }
        
        Ok(())
    }
}

fn main() {
    let mut validator = ResourceLockValidator::new();
    let user = [1u8; 20];
    let resource = [2u8; 20];
    let legitimate_target = vec![2u8; 20];
    let attacker_target = vec![99u8; 20]; // Different target!
    
    validator.add_lock(user, ResourceLock {
        resource,
        max_amount: 1000,
        target_call: legitimate_target,
    });
    
    // Attacker crafts userOp with different target but same resource
    let malicious_op = UserOperation {
        sender: user,
        nonce: 1,
        call_data: {
            let mut data = vec![0u8; 4]; // selector
            data.extend_from_slice(&attacker_target); // DIFFERENT target - should fail!
            data.extend_from_slice(&100u64.to_be_bytes()); // amount within limit
            data
        },
        signature: vec![],
    };
    
    // VULNERABLE: This passes when it should fail!
    let result = validator.validate_user_op(&malicious_op);
    assert!(result.is_ok(), "Bug: validation passed for mismatched target");
    println!("Vulnerable fixture demonstrates missing scope binding");
}