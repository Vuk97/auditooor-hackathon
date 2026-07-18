use std::collections::{HashMap, HashSet};

type Address = [u8; 20];
type Hash32 = [u8; 32];

pub struct Message {
    pub sender: Address,
    pub recipient: Address,
    pub value: u128,
    pub fee: u128,
    pub data: Vec<u8>,
}

pub struct SignalService {
    signals: HashMap<Hash32, Vec<u8>>,
}

impl SignalService {
    pub fn send_bridge_signal(&mut self, msg: &Message) -> Hash32 {
        let hash_input = [
            &msg.sender[..],
            &msg.recipient[..],
            &msg.value.to_be_bytes()[..],
            &msg.fee.to_be_bytes()[..],
            &msg.data,
        ]
        .concat();
        let signal_hash = keccak256(&hash_input);
        self.signals.insert(signal_hash, msg.data.clone());
        signal_hash
    }
}

pub struct Any2EVMMessage {
    pub source_chain_selector: u64,
    pub token_amounts: Vec<TokenAmount>,
    pub data: Vec<u8>,
}

pub struct TokenAmount {
    pub amount: u128,
}

pub struct BridgeCCIP {
    allowed_source_chains: HashSet<u64>,
    total_minted: u128,
}

impl BridgeCCIP {
    pub fn ccip_receive(&mut self, message: Any2EVMMessage) -> Result<(), &'static str> {
        if !self.allowed_source_chains.contains(&message.source_chain_selector) {
            return Err("source chain not allowed");
        }
        for token_amount in &message.token_amounts {
            self.total_minted = self.total_minted.saturating_add(token_amount.amount);
        }
        let _ = message.data;
        Ok(())
    }
}

pub struct BridgeVerifier;

impl BridgeVerifier {
    pub fn validator_set_checkpoint_hash(
        validator_set: Vec<u8>,
        checkpoint: u64,
        chain_id: u64,
        signatures: Vec<Vec<u8>>,
    ) -> Hash32 {
        sha256(&(chain_id, checkpoint, validator_set, signatures))
    }
}

fn keccak256(_input: &[u8]) -> Hash32 {
    [0u8; 32]
}

fn sha256(_input: &(u64, u64, Vec<u8>, Vec<Vec<u8>>)) -> Hash32 {
    [0u8; 32]
}
