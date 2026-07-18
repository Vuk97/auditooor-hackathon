use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Adapter;
impl Adapter { fn lz_receive(&self, _payload: &[u8]) {} }
fn load_adapter() -> Adapter { Adapter }
fn configured_executor() -> Address { [0; 20] }
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn lz_receive(caller: Address, payload: Vec<u8>) {
        assert!(caller == configured_executor(), "not the configured executor");
        let adapter = load_adapter();
        adapter.lz_receive(&payload);
    }
}
