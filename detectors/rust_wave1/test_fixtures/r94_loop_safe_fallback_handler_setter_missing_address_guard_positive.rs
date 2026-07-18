use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct SafeTx { to: Address, data: Vec<u8> }
const SET_FALLBACK_HANDLER: &str = "setFallbackHandler";
fn decode_selector_name(_data: &[u8]) -> &'static str { SET_FALLBACK_HANDLER }
#[contract]
pub struct ReNftGuard;
#[contractimpl]
impl ReNftGuard {
    // BUG: detects setFallbackHandler call but does not validate handler address or revert
    pub fn check_transaction(safe_tx: SafeTx) -> bool {
        let method = decode_selector_name(&safe_tx.data);
        if method == SET_FALLBACK_HANDLER {
            // No whitelist / revert — caller can set any fallback handler
            return true;
        }
        true
    }
}
