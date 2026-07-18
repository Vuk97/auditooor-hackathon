use soroban_sdk::{contract, contractimpl};

pub struct Config { required_dvn_count: u8 }
fn load_config() -> Config { Config { required_dvn_count: 3 } }
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn verify(signatures: Vec<[u8; 65]>) -> bool {
        let config = load_config();
        assert!(config.required_dvn_count >= 2, "quorum too small");
        signatures.len() as u8 >= config.required_dvn_count
    }
}
