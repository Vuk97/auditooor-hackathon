use soroban_sdk::{contract, contractimpl};

pub struct UlnConfig { required_dvn_count: u8, optional_dvn_count: u8 }
fn save_config(_c: &UlnConfig) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn set_config(c: UlnConfig) {
        assert!(c.required_dvn_count >= 2, "unsafe DVN threshold");
        save_config(&c);
    }
}
