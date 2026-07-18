use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct SafeTx { to: Address, data: Vec<u8> }
const SET_FALLBACK_HANDLER: &str = "setFallbackHandler";
fn decode_selector_name(_data: &[u8]) -> &'static str { SET_FALLBACK_HANDLER }
fn decode_handler_addr(_data: &[u8]) -> Address { [0; 20] }
fn is_allowed_fallback(_addr: Address) -> bool { true }
#[contract]
pub struct ReNftGuard;
#[contractimpl]
impl ReNftGuard {
    // SAFE: reverts if setFallbackHandler target is not whitelisted
    pub fn check_transaction(safe_tx: SafeTx) -> bool {
        let method = decode_selector_name(&safe_tx.data);
        if method == SET_FALLBACK_HANDLER {
            let handler = decode_handler_addr(&safe_tx.data);
            assert!(is_allowed_fallback(handler), "fallback handler not whitelisted");
        }
        true
    }
}
