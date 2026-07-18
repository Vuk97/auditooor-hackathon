use std::collections::HashMap;
use alloy_primitives::{keccak256, FixedBytes, U256};

/// Clean: signal hash is bound to message value+fee, preventing collision attacks.
pub struct SignalService {
    signals: HashMap<FixedBytes<32>, SignalData>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignalData {
    pub sender: [u8; 20],
    pub value: U256,
    pub fee: U256,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub sender: [u8; 20],
    pub recipient: [u8; 20],
    pub value: U256,
    pub fee: U256,
    pub data: Vec<u8>,
}

impl SignalService {
    pub fn new() -> Self {
        Self {
            signals: HashMap::new(),
        }
    }

    /// Bind the hash to value+fee so attacker cannot swap values with same hash.
    pub fn send_signal(&mut self, msg: &Message) -> FixedBytes<32> {
        let signal_data = SignalData {
            sender: msg.sender,
            value: msg.value,
            fee: msg.fee,
            message: msg.data.clone(),
        };
        // Hash includes value and fee — bound to financial parameters
        let hash_input = [
            &msg.sender[..],
            &msg.recipient[..],
            &msg.value.to_be_bytes::<32>()[..],
            &msg.fee.to_be_bytes::<32>()[..],
            &msg.data,
        ]
        .concat();
        let signal_hash = keccak256(&hash_input);
        self.signals.insert(signal_hash, signal_data);
        signal_hash
    }

    pub fn process_message(&mut self, msg: &Message) -> Result<U256, &'static str> {
        let hash_input = [
            &msg.sender[..],
            &msg.recipient[..],
            &msg.value.to_be_bytes::<32>()[..],
            &msg.fee.to_be_bytes::<32>()[..],
            &msg.data,
        ]
        .concat();
        let signal_hash = keccak256(&hash_input);

        let stored = self.signals.get(&signal_hash).ok_or("Signal not found")?;

        // Verify stored value matches — hash binding ensures this, but defense in depth
        if stored.value != msg.value || stored.fee != msg.fee {
            return Err("Value/fee mismatch");
        }

        let total = msg.value + msg.fee;
        self.signals.remove(&signal_hash);
        Ok(total)
    }
}

fn main() {
    let mut service = SignalService::new();
    let msg = Message {
        sender: [1u8; 20],
        recipient: [2u8; 20],
        value: U256::from(100),
        fee: U256::from(10),
        data: vec![0xab, 0xcd],
    };
    let hash = service.send_signal(&msg);
    let result = service.process_message(&msg).unwrap();
    assert_eq!(result, U256::from(110));
    println!("Clean test passed: hash={:?}", hash);
}