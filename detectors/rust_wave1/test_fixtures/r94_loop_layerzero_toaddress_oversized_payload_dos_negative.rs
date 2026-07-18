use soroban_sdk::{contract, contractimpl};
fn pack_payload(_to_address: &[u8], _amount: u64) -> Vec<u8> { Vec::new() }
fn lz_endpoint_send(_dst_chain: u16, _payload: &[u8]) {}
#[contract]
pub struct OftCore;
#[contractimpl]
impl OftCore {
    // SAFE: enforces to_address.len() <= 32 before packing
    pub fn send_from(dst_chain: u16, to_address: Vec<u8>, amount: u64) {
        assert!(to_address.len() <= 32, "to_address too long");
        let payload = pack_payload(&to_address, amount);
        lz_endpoint_send(dst_chain, &payload);
    }
}
