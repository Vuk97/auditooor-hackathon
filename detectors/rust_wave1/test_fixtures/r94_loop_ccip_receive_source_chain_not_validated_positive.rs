use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct BridgeCCIP;
#[contractimpl]
impl BridgeCCIP {
    // BUG: processes any2evm_message without checking source_chain_selector
    pub fn ccip_receive(message: Any2EvmMessage) {
        let _ = message.data;
        process(message);
    }
}
pub struct Any2EvmMessage { pub data: u128, pub source_chain_selector: u64 }
fn process(_m: Any2EvmMessage) {}
