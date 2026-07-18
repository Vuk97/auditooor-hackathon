use soroban_sdk::{contract, contractimpl};

pub struct Config { required_dvn_count: u8 }
fn load_config() -> Config { Config { required_dvn_count: 1 } }
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn verify(signatures: Vec<[u8; 65]>) -> bool {
        let config = load_config();
        signatures.len() as u8 >= config.required_dvn_count
    }
}
