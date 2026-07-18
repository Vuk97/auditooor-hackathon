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

    pub fn validate_user_op(&self, user_op: &UserOperation) -> Result<(), &'static str> {
        let user_locks = self.locks.get(&user_op.sender).ok_or("No locks found")?;
        
        for lock in user_locks {
            // Extract target from call_data (first 20 bytes after selector)
            if user_op.call_data.len() < 24 {
                return Err("Invalid call data");
            }
            let call_target = &user_op.call_data[4..24];
            
            // CRITICAL FIX: Bind resource-lock scope to target call
            // Verify the call target matches the locked resource
            if call_target != &lock.target_call[..] {
                return Err("Call target does not match locked resource scope");
            }
            
            // Verify the resource being accessed matches the lock
            let accessed_resource = &user_op.call_data[4..24];
            if accessed_resource != lock.resource.as_slice() {
                return Err("Accessed resource does not match lock");
            }
            
            // Check amount is within limit
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
        }
        
        Ok(())
    }
}

fn main() {
    let mut validator = ResourceLockValidator::new();
    let user = [1u8; 20];
    let resource = [2u8; 20];
    let target = vec![2u8; 20];
    
    validator.add_lock(user, ResourceLock {
        resource,
        max_amount: 1000,
        target_call: target.clone(),
    });
    
    let user_op = UserOperation {
        sender: user,
        nonce: 1,
        call_data: {
            let mut data = vec![0u8; 4]; // selector
            data.extend_from_slice(&resource); // target matches lock
            data.extend_from_slice(&100u64.to_be_bytes()); // amount within limit
            data
        },
        signature: vec![],
    };
    
    assert!(validator.validate_user_op(&user_op).is_ok());
    println!("Clean fixture passed");
}