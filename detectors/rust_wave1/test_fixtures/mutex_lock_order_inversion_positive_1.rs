// POSITIVE: Classic ABBA lock-order inversion.
// fn transfer() acquires `accounts` then `ledger`.
// fn reconcile() acquires `ledger` then `accounts`.
// If both run concurrently, deadlock.

use std::sync::{Arc, Mutex};

struct Bank {
    accounts: Arc<Mutex<Vec<u64>>>,
    ledger: Arc<Mutex<Vec<String>>>,
}

impl Bank {
    // acquires: accounts -> ledger
    pub fn transfer(&self, from: usize, to: usize, amount: u64) {
        let mut accounts = self.accounts.lock().unwrap();
        let mut ledger = self.ledger.lock().unwrap();
        if accounts[from] >= amount {
            accounts[from] -= amount;
            accounts[to] += amount;
            ledger.push(format!("transfer {} {} {}", from, to, amount));
        }
    }

    // acquires: ledger -> accounts  (INVERTED order!)
    pub fn reconcile(&self) {
        let ledger = self.ledger.lock().unwrap();
        let accounts = self.accounts.lock().unwrap();
        println!("ledger entries: {}, accounts: {}", ledger.len(), accounts.len());
    }
}
