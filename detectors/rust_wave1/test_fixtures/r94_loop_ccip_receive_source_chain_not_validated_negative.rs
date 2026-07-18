use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBridgeCCIP;
#[contractimpl]
impl SafeBridgeCCIP {
    // OK: checks allowed_chain(source_chain_selector) before processing
    pub fn ccip_receive(message: Any2EvmMessage) {
        if !allowed_chain(message.source_chain_selector) { panic!("bad source"); }
        let _ = message.data;
        process(message);
    }
}
pub struct Any2EvmMessage { pub data: u128, pub source_chain_selector: u64 }
fn allowed_chain(_c: u64) -> bool { true }
fn process(_m: Any2EvmMessage) {}
