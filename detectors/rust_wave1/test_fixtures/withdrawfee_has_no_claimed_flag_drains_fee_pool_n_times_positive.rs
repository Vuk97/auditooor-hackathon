use std::collections::HashMap;

pub struct FeePool {
    pub balance: u64,
    pub fee_per_participant: u64,
    pub participant_count: u64,
    // NOTE: No `fee_withdrawn` claimed flag!
}

impl FeePool {
    pub fn new(balance: u64, fee_per_participant: u64, participants: u64) -> Self {
        Self {
            balance,
            fee_per_participant,
            participant_count: participants,
        }
    }

    pub fn withdraw_fee(&mut self, caller: &mut Account) -> Result<(), &'static str> {
        // VULNERABLE: No check for whether fee was already withdrawn
        let fee = self.participant_count.checked_mul(self.fee_per_participant)
            .ok_or("Overflow")?;
        
        if fee > self.balance {
            return Err("Insufficient balance");
        }
        
        self.balance -= fee;
        caller.balance += fee;
        // Missing: self.fee_withdrawn = true;
        
        Ok(())
    }
}

pub struct Account {
    pub balance: u64,
}

fn main() {
    let mut pool = FeePool::new(10000, 100, 50);
    let mut treasury = Account { balance: 0 };
    
    // First withdrawal succeeds
    pool.withdraw_fee(&mut treasury).unwrap();
    assert_eq!(treasury.balance, 5000);
    assert_eq!(pool.balance, 5000);
    
    // VULNERABLE: Second withdrawal also succeeds, draining pool
    pool.withdraw_fee(&mut treasury).unwrap();
    assert_eq!(treasury.balance, 10000);
    assert_eq!(pool.balance, 0);
    
    // Can be called repeatedly until balance insufficient
    assert!(pool.withdraw_fee(&mut treasury).is_err());
}