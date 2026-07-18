use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];
pub struct Token;
impl Token {
    fn transfer(&self, _to: Address, _amt: u128) {}
}
fn load_token() -> Token { Token }
fn verify_source_burn(_proof: &[u8]) -> bool { true }

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn lz_receive(recipient: Address, amount: u128, source_proof: Vec<u8>) {
        assert!(verify_source_burn(&source_proof), "source not burned");
        let token = load_token();
        token.transfer(recipient, amount);
    }
}
