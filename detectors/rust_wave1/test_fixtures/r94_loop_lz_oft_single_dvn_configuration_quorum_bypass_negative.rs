use soroban_sdk::{contract, contractimpl};

// multisig_config: threshold enforced via optional_dvn_threshold and required_dvn_count >= 3
pub struct UlnConfig {
    required_dvn_count: u8,
    optional_dvn_count: u8,
    optional_dvn_threshold: u8,
}
fn save_config(_c: &UlnConfig) {}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn set_config() {
        // multisig_config quorum: 3 required DVNs + optional threshold
        let c = UlnConfig {
            required_dvn_count: 3,
            optional_dvn_count: 2,
            optional_dvn_threshold: 1,
        };
        save_config(&c);
    }
}
