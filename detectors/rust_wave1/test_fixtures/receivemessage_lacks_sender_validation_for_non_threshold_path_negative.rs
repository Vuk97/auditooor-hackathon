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
        // Always validate sender regardless of threshold
        if !self.authorized_senders.get(&message.sender).copied().unwrap_or(false) {
            return Err("Unauthorized sender");
        }

        if message.threshold == 1 {
            // Single threshold path - additional validation already done above
            self.execute_transfer(message)?;
        } else {
            // Multi-threshold path - sender already validated above
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
    controller.add_authorized_sender(authorized);
    
    let msg = Message {
        sender: authorized,
        recipient: [2u8; 32],
        amount: 100,
        threshold: 2,
        payload: vec![],
    };
    
    assert!(controller.receive_message(&msg).is_ok());
    println!("Clean version works correctly");
}