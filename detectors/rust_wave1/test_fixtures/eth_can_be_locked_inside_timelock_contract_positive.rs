use std::collections::HashMap;

pub struct Timelock {
    queued_transactions: HashMap<[u8; 32], QueuedTx>,
}

struct QueuedTx {
    target: [u8; 20],
    value: u64,
    data: Vec<u8>,
    executed: bool,
}

impl Timelock {
    pub fn new() -> Self {
        Self {
            queued_transactions: HashMap::new(),
        }
    }

    pub fn queue_transaction(
        &mut self,
        tx_hash: [u8; 32],
        target: [u8; 20],
        value: u64,
        data: Vec<u8>,
    ) {
        self.queued_transactions.insert(
            tx_hash,
            QueuedTx {
                target,
                value,
                data,
                executed: false,
            },
        );
    }

    pub fn execute_transaction(
        &mut self,
        tx_hash: [u8; 32],
        received_value: u64,
    ) -> Result<(), &'static str> {
        let tx = self.queued_transactions
            .get_mut(&tx_hash)
            .ok_or("Transaction not found")?;
        
        if tx.executed {
            return Err("Already executed");
        }

        let required = tx.value;
        
        if received_value < required {
            return Err("Insufficient value sent");
        }

        tx.executed = true;
        
        self.transfer_native(tx.target, required)?;
        
        Ok(())
    }

    fn transfer_native(&mut self, _to: [u8; 20], _amount: u64) -> Result<(), &'static str> {
        Ok(())
    }
}

fn main() {
    let mut timelock = Timelock::new();
    let tx_hash = [1u8; 32];
    timelock.queue_transaction(tx_hash, [2u8; 20], 100, vec![1, 2, 3]);
    let _ = timelock.execute_transaction(tx_hash, 150);
}