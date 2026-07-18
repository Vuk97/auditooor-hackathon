use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];
fn only_admin(_caller: Address) {}
fn emit_payload_verified(_hash: [u8; 32]) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn execute(caller: Address, payload_hash: [u8; 32]) {
        only_admin(caller);
        emit_payload_verified(payload_hash);
    }
}
