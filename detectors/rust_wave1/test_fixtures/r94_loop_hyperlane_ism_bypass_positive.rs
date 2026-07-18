use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Router;
#[contractimpl]
impl Router {
    // BUG: hyperlane mailbox context, no ism.verify
    pub fn handle(origin: u32, sender: [u8; 32], message: Vec<u8>) {
        let _mailbox = "hyperlane";
        dispatch(message);
    }
}
fn dispatch(_m: Vec<u8>) {}
