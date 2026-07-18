use std::collections::HashMap;

pub struct Message {
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
    pub threshold: u8,
    pub payload: Vec<u8>,
}

pub struct AssetController {
    pub authorized_senders: HashMap<[u8; 32], bool>,
    pub balances: HashMap<[u8; 32], u64>,
}

impl AssetController {
    pub fn new() -> Self {
        Self {
            authorized_senders: HashMap::new(),
            balances: HashMap::new(),
        }
    }

    pub fn add_authorized_sender(&mut self, sender: [u8; 32]) {
        self.authorized_senders.insert(sender, true);
    }

    pub fn receive_message(&mut self, message: &Message) -> Result<(), &'static str> {
        // BUG: Sender validation only occurs when threshold == 1
        // Missing validation for non-threshold (multi-threshold) path
        if message.threshold == 1 {
            if !self.authorized_senders.get(&message.sender).copied().unwrap_or(false) {
                return Err("Unauthorized sender");
            }
            self.execute_transfer(message)?;
        } else {
            // VULNERABLE: No sender check here - any caller can inject messages
            self.execute_transfer(message)?;
        }

        Ok(())
    }

    fn execute_transfer(&mut self, message: &Message) -> Result<(), &'static str> {
        let balance = self.balances.entry(message.recipient).or_insert(0);
        *balance = balance.checked_add(message.amount).ok_or("Overflow")?;
        Ok(())
    }
}

fn main() {
    let mut controller = AssetController::new();
    let authorized = [1u8; 32];
    let attacker = [99u8; 32];
    controller.add_authorized_sender(authorized);
    
    // Attacker can forge message with threshold != 1 without authorization
    let malicious_msg = Message {
        sender: attacker, // Unauthorized sender
        recipient: attacker,
        amount: 1000,
        threshold: 2, // Non-threshold path bypasses validation
        payload: vec![],
    };
    
    // This succeeds when it should fail - unauthorized mint/transfer
    assert!(controller.receive_message(&malicious_msg).is_ok());
    println!("Vulnerable version allows unauthorized access");
}