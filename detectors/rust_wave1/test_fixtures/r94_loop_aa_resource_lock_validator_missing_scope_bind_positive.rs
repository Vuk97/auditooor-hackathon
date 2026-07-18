use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct ResourceLock { target: Address, selector: [u8; 4], amount: u64 }
pub struct UserOp { sender: Address, call_data: Vec<u8>, signature: Vec<u8> }
fn verify_sig(_op: &UserOp) -> bool { true }
fn load_resource_lock(_sender: Address) -> ResourceLock {
    ResourceLock { target: [0; 20], selector: [0; 4], amount: 0 }
}
#[contract]
pub struct ResourceLockValidator;
#[contractimpl]
impl ResourceLockValidator {
    // BUG: retrieves the resource_lock but never binds its scope to op.call_data
    pub fn validate_user_op(op: UserOp) -> bool {
        let resource_lock = load_resource_lock(op.sender);
        let _ = resource_lock.target;
        let _ = resource_lock.selector;
        verify_sig(&op)
    }
}
