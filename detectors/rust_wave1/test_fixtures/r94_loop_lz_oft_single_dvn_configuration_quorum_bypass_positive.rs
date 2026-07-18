use soroban_sdk::{contract, contractimpl};

pub struct UlnConfig { required_dvn_count: u8, optional_dvn_count: u8 }
fn save_config(_c: &UlnConfig) {}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn set_config() {
        let c = UlnConfig { required_dvn_count: 1, optional_dvn_count: 0 };
        save_config(&c);
    }
}
