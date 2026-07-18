use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeHandler;
#[contractimpl]
impl SafeHandler {
    // OK: validates length before decode
    pub fn decode_reason(reason: &[u8]) -> String {
        if reason.len() <= 256 {
            let s = String::from_utf8(reason.to_vec()).unwrap_or_default();
            return s;
        }
        String::new()
    }
}
