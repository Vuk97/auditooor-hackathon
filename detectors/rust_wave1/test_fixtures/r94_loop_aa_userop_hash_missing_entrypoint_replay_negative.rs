use soroban_sdk::{contract, contractimpl};
pub struct UserOp { sender: [u8; 20], nonce: u64, call_data: Vec<u8>, signature: Vec<u8> }
pub struct Env;
impl Env {
    fn chain_id(&self) -> u64 { 1 }
    fn entry_point(&self) -> [u8; 20] { [0; 20] }
}
fn keccak256(_: &[u8]) -> [u8; 32] { [0; 32] }
fn abi_encode(_: &UserOp, _entrypoint: [u8; 20], _chain_id: u64) -> Vec<u8> { Vec::new() }
#[contract]
pub struct EntryPoint;
#[contractimpl]
impl EntryPoint {
    // SAFE: binds entryPoint + chainId into userOpHash
    pub fn get_user_op_hash(env: &Env, op: UserOp) -> [u8; 32] {
        let entry_point = env.entry_point();
        let chain_id = env.chain_id();
        let encoded = abi_encode(&op, entry_point, chain_id);
        keccak256(&encoded)
    }
}
