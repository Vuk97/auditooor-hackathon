use soroban_sdk::{contract, contractimpl};
pub struct ValidationModule { signature_validation_enabled: bool }
pub struct UserOp { sender: [u8; 20], data: Vec<u8>, signature: Vec<u8> }
fn verify_user_op_sig(_op: &UserOp) -> bool { true }
fn verify_signature_validation(_op: &UserOp) -> bool { true }
fn pre_validation_hook(_op: &UserOp) {}
#[contract]
pub struct Account;
#[contractimpl]
impl Account {
    // SAFE: pre_validation_hook runs on both branches
    pub fn validate_user_op(module: &ValidationModule, op: UserOp) -> bool {
        if module.signature_validation_enabled {
            pre_validation_hook(&op);
            return verify_signature_validation(&op);
        }
        pre_validation_hook(&op);
        verify_user_op_sig(&op)
    }
}
