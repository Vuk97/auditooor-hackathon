use std::collections::HashMap;
use alloy_primitives::{keccak256, FixedBytes, U256};

/// Vulnerable: signal hash only covers message data, NOT value+fee.
/// Attacker can craft message with same hash but different value to drain.
pub struct SignalService {
    signals: HashMap<FixedBytes<32>, SignalData>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignalData {
    pub sender: [u8; 20],
    pub message: Vec<u8>,
    // NOTE: value and fee are NOT stored in signal data — only checked against message
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

    /// BUG: Hash only includes message data, not value/fee. Attacker can replay with different value.
    pub fn send_signal(&mut self, msg: &Message) -> FixedBytes<32> {
        let signal_data = SignalData {
            sender: msg.sender,
            message: msg.data.clone(),
        };
        // VULNERABLE: hash does NOT include value or fee
        let hash_input = [&msg.sender[..], &msg.recipient[..], &msg.data].concat();
        let signal_hash = keccak256(&hash_input);
        self.signals.insert(signal_hash, signal_data);
        signal_hash
    }

    pub fn process_message(&mut self, msg: &Message) -> Result<U256, &'static str> {
        // VULNERABLE: same weak hash — attacker can pass different value/fee
        let hash_input = [&msg.sender[..], &msg.recipient[..], &msg.data].concat();
        let signal_hash = keccak256(&hash_input);

        // Only checks existence, NOT that stored value matches
        let _stored = self.signals.get(&signal_hash).ok_or("Signal not found")?;

        // No validation that msg.value matches what was originally signaled!
        let total = msg.value + msg.fee;
        self.signals.remove(&signal_hash);
        Ok(total)
    }
}

fn main() {
    let mut service = SignalService::new();

    // Original message with small value
    let original_msg = Message {
        sender: [1u8; 20],
        recipient: [2u8; 20],
        value: U256::from(100),
        fee: U256::from(10),
        data: vec![0xab, 0xcd],
    };
    let _hash = service.send_signal(&original_msg);

    // ATTACK: Same hash input (sender, recipient, data) but DIFFERENT value
    let forged_msg = Message {
        sender: [1u8; 20],
        recipient: [2u8; 20],
        value: U256::from(1000000), // Drained amount!
        fee: U256::from(0),
        data: vec![0xab, 0xcd], // Same data = same hash
    };

    // Exploit succeeds — hash matches, value is not validated
    let stolen = service.process_message(&forged_msg).unwrap();
    println!("VULNERABLE: Attacker drained: {}", stolen);
    assert_eq!(stolen, U256::from(1000000));
}