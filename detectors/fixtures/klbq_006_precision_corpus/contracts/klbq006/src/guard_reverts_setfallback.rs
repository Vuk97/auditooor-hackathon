use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

pub struct SafeTx {
    data: Vec<u8>,
}

const SET_FALLBACK_HANDLER: &str = "setFallbackHandler";

fn decode_selector_name(_data: &[u8]) -> &'static str {
    SET_FALLBACK_HANDLER
}

fn decode_handler_addr(_data: &[u8]) -> Address {
    [7; 20]
}

fn is_allowed_fallback(_handler: Address) -> bool {
    true
}

#[contract]
pub struct GuardRevertsSetFallback;

#[contractimpl]
impl GuardRevertsSetFallback {
    pub fn check_transaction(safe_tx: SafeTx) -> bool {
        let selector = decode_selector_name(&safe_tx.data);
        if selector == SET_FALLBACK_HANDLER {
            let handler = decode_handler_addr(&safe_tx.data);
            if !is_allowed_fallback(handler) {
                panic!("fallback handler not allowed");
            }
        }
        true
    }
}
