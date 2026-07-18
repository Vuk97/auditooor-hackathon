use std::collections::HashMap;

/// Simulates LayerZero-style remote transfer where 'from' is extracted
/// from the attested payload, not caller-controlled parameters.
pub struct RemoteTransfer {
    balances: HashMap<[u8; 32], u64>,
}

#[derive(Clone, Debug)]
pub struct AttestedPayload {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub nonce: u64,
}

impl RemoteTransfer {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
        }
    }

    pub fn deposit(&mut self, addr: [u8; 32], amount: u64) {
        *self.balances.entry(addr).or_insert(0) += amount;
    }

    /// CORRECT: 'from' is decoded from the LayerZero-attested payload,
    /// which cannot be forged by the caller.
    pub fn remote_transfer(
        &mut self,
        _caller: [u8; 32],
        payload: AttestedPayload,
    ) -> Result<(), &'static str> {
        let from = payload.from; // from attested payload
        let to = payload.to;
        let amount = payload.amount;

        let sender_balance = self.balances.get_mut(&from).ok_or("No balance")?;
        if *sender_balance < amount {
            return Err("Insufficient balance");
        }
        *sender_balance -= amount;
        *self.balances.entry(to).or_insert(0) += amount;
        Ok(())
    }
}

fn main() {
    let mut rt = RemoteTransfer::new();
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    rt.deposit(alice, 1000);
    
    let payload = AttestedPayload {
        from: alice,
        to: bob,
        amount: 500,
        nonce: 1,
    };
    // Even if malicious caller passes their own address, it doesn't matter
    let malicious = [99u8; 32];
    rt.remote_transfer(malicious, payload).unwrap();
    
    assert_eq!(rt.balances.get(&alice), Some(&500));
    assert_eq!(rt.balances.get(&bob), Some(&500));
}