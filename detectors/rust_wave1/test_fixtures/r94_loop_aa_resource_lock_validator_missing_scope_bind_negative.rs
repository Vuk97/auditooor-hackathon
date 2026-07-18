use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct ResourceLock { target: Address, selector: [u8; 4], amount: u64 }
pub struct UserOp { sender: Address, call_data: Vec<u8>, signature: Vec<u8> }
fn verify_sig(_op: &UserOp) -> bool { true }
fn load_resource_lock(_sender: Address) -> ResourceLock {
    ResourceLock { target: [0; 20], selector: [0; 4], amount: 0 }
}
fn extract_target(_call_data: &[u8]) -> Address { [0; 20] }
fn extract_selector(call_data: &[u8]) -> [u8; 4] {
    let mut s = [0u8; 4];
    s.copy_from_slice(&call_data[0..4]);
    s
}
#[contract]
pub struct ResourceLockValidator;
#[contractimpl]
impl ResourceLockValidator {
    // SAFE: binds lock.target / lock.selector to op.call_data before authorizing
    pub fn validate_user_op(op: UserOp) -> bool {
        let resource_lock = load_resource_lock(op.sender);
        let op_target = extract_target(&op.call_data);
        let op_selector = extract_selector(&op.call_data);
        assert!(resource_lock.target == op_target, "target mismatch");
        assert!(resource_lock.selector == op_selector, "selector mismatch");
        verify_sig(&op)
    }
}
