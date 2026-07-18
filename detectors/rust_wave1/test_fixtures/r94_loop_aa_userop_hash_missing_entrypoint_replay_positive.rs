use soroban_sdk::{contract, contractimpl};
pub struct UserOp { sender: [u8; 20], nonce: u64, call_data: Vec<u8>, signature: Vec<u8> }
fn keccak256(_: &[u8]) -> [u8; 32] { [0; 32] }
fn abi_encode(_: &UserOp) -> Vec<u8> { Vec::new() }
#[contract]
pub struct EntryPoint;
#[contractimpl]
impl EntryPoint {
    // BUG: userOpHash omits entryPoint AND chainId
    pub fn get_user_op_hash(op: UserOp) -> [u8; 32] {
        let encoded = abi_encode(&op);
        keccak256(&encoded)
    }
}
