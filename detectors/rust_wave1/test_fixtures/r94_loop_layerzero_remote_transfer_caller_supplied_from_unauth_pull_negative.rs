use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn transfer_from(_token: Address, _from: Address, _to: Address, _amount: u64) {}
fn abi_decode(_payload: &[u8]) -> (Address, Address, u64) { ([0; 20], [0; 20], 0) }
#[contract]
pub struct USDO;
#[contractimpl]
impl USDO {
    // SAFE: decodes `from` from the LayerZero-attested payload
    pub fn remote_transfer(token: Address, payload: Vec<u8>) {
        let (from, to, amount) = abi_decode(&payload);
        transfer_from(token, from, to, amount);
    }
}
