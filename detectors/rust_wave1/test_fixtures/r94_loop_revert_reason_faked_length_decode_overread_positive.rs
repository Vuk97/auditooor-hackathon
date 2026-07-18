use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Handler;
#[contractimpl]
impl Handler {
    // BUG: decodes reason as string without verifying length prefix
    pub fn decode_reason(reason: &[u8]) -> String {
        let s = String::from_utf8(reason.to_vec()).unwrap_or_default();
        s
    }
}
