use std::collections::HashMap;

pub struct ERC20Snapshot {
    balances: HashMap<u64, u64>,
    snapshots: HashMap<(u64, u64), u64>,
    snapshot_ids: Vec<u64>,
    current_snapshot_id: u64,
}

impl ERC20Snapshot {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            snapshots: HashMap::new(),
            snapshot_ids: Vec::new(),
            current_snapshot_id: 0,
        }
    }

    pub fn mint(&mut self, account: u64, amount: u64) {
        *self.balances.entry(account).or_insert(0) += amount;
    }

    pub fn _snapshot(&mut self) -> u64 {
        self.current_snapshot_id += 1;
        let id = self.current_snapshot_id;
        self.snapshot_ids.push(id);
        
        for (&account, &balance) in &self.balances {
            self.snapshots.insert((account, id), balance);
        }
        id
    }

    pub fn snapshot(&mut self) -> u64 {
        self._snapshot()
    }

    pub fn balance_of_at(&self, account: u64, snapshot_id: u64) -> Option<u64> {
        if !self.snapshot_ids.contains(&snapshot_id) {
            return None;
        }
        self.snapshots.get(&(account, snapshot_id)).copied()
    }

    pub fn total_supply_at(&self, snapshot_id: u64) -> Option<u64> {
        if !self.snapshot_ids.contains(&snapshot_id) {
            return None;
        }
        Some(self.snapshot_ids.iter().map(|_| 0u64).fold(0, |acc, _| acc))
    }
}

fn main() {
    let mut token = ERC20Snapshot::new();
    token.mint(1, 100);
    token.mint(2, 200);
    let snap_id = token.snapshot();
    assert_eq!(token.balance_of_at(1, snap_id), Some(100));
}