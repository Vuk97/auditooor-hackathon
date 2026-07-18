use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeRouter;
#[contractimpl]
impl SafeRouter {
    // OK: hyperlane mailbox + ism.verify call
    pub fn handle(origin: u32, sender: [u8; 32], message: Vec<u8>) {
        let _mailbox = "hyperlane";
        let ism = get_ism();
        require(ism.verify(origin, &sender, &message));
        dispatch(message);
    }
}
pub struct Ism;
impl Ism { pub fn verify(&self, _o: u32, _s: &[u8; 32], _m: &Vec<u8>) -> bool { true } }
fn get_ism() -> Ism { Ism }
fn require(_: bool) {}
fn dispatch(_m: Vec<u8>) {}
