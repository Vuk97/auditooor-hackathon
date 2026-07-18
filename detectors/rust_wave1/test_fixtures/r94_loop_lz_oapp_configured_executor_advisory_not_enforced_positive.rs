use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Adapter;
impl Adapter { fn lz_receive(&self, _payload: &[u8]) {} }
fn load_adapter() -> Adapter { Adapter }
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn lz_receive(payload: Vec<u8>) {
        let adapter = load_adapter();
        adapter.lz_receive(&payload);
    }
}
