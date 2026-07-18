use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

fn _safe_mint(_to: Address, _id: u64) {}
fn burn_packet(_id: u64) {}
fn non_reentrant() {}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn open_packet(caller: Address, packet_id: u64) {
        non_reentrant();
        let card_id: u64 = packet_id;
        burn_packet(packet_id);
        _safe_mint(caller, card_id);
    }
}
