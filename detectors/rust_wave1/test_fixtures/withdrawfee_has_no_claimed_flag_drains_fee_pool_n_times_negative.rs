use std::collections::HashMap;

pub struct FeePool {
    pub balance: u64,
    pub fee_per_participant: u64,
    pub fee_withdrawn: bool,
    pub participant_count: u64,
}

impl FeePool {
    pub fn new(balance: u64, fee_per_participant: u64, participants: u64) -> Self {
        Self {
            balance,
            fee_per_participant,
            fee_withdrawn: false,
            participant_count: participants,
        }
    }

    pub fn withdraw_fee(&mut self, caller: &mut Account) -> Result<(), &'static str> {
        if self.fee_withdrawn {
            return Err("Fee already withdrawn");
        }
        
        let fee = self.participant_count.checked_mul(self.fee_per_participant)
            .ok_or("Overflow")?;
        
        if fee > self.balance {
            return Err("Insufficient balance");
        }
        
        self.balance -= fee;
        caller.balance += fee;
        self.fee_withdrawn = true;
        
        Ok(())
    }
}

pub struct Account {
    pub balance: u64,
}

fn main() {
    let mut pool = FeePool::new(10000, 100, 50);
    let mut treasury = Account { balance: 0 };
    
    pool.withdraw_fee(&mut treasury).unwrap();
    assert_eq!(treasury.balance, 5000);
    assert_eq!(pool.balance, 5000);
    
    // Second attempt fails due to claimed flag
    assert!(pool.withdraw_fee(&mut treasury).is_err());
    assert_eq!(treasury.balance, 5000); // unchanged
}