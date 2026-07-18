use std::collections::HashMap;

/// VULNERABLE: 'from' address is read from caller-controlled parameter
/// instead of the LayerZero-attested payload, enabling balance theft.
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

    /// VULNERABLE: 'from' is taken from caller-controlled 'from_addr'
    /// parameter instead of payload.from, allowing attacker to drain
    /// any user's balance by supplying their address.
    pub fn remote_transfer(
        &mut self,
        _caller: [u8; 32],
        from_addr: [u8; 32], // BUG: caller-controlled 'from'
        payload: AttestedPayload,
    ) -> Result<(), &'static str> {
        let from = from_addr; // BUG: using caller-supplied instead of payload.from
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
        from: alice, // attested as from alice, but ignored!
        to: bob,
        amount: 500,
        nonce: 1,
    };
    // Attacker can steal alice's balance by passing alice as from_addr
    let malicious = [99u8; 32];
    rt.remote_transfer(malicious, alice, payload).unwrap(); // steals from alice!
    
    assert_eq!(rt.balances.get(&alice), Some(&500));
    assert_eq!(rt.balances.get(&bob), Some(&500));
}