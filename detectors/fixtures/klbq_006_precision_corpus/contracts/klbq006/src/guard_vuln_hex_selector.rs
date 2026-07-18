use soroban_sdk::{contract, contractimpl};

pub struct SafeTx {
    data: Vec<u8>,
}

fn selector_hex(_data: &[u8]) -> &'static str {
    "0xf08a0323"
}

#[contract]
pub struct GuardVulnHexSelector;

#[contractimpl]
impl GuardVulnHexSelector {
    pub fn check_transaction(safe_tx: SafeTx) -> bool {
        let selector = selector_hex(&safe_tx.data);
        if selector == "0xf08a0323" {
            return true;
        }
        true
    }
}
