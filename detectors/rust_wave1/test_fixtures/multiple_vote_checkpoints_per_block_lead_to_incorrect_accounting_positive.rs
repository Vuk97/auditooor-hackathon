use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
struct Checkpoint {
    timestamp: u64,
    votes: u64,
}

#[derive(Clone, Debug, Default)]
struct VoteLedger {
    checkpoints: Vec<Checkpoint>,
}

impl VoteLedger {
    fn write_checkpoint(&mut self, timestamp: u64, votes: u64) {
        // BUG: always pushes new checkpoint, even with same timestamp
        self.checkpoints.push(Checkpoint { timestamp, votes });
    }

    fn get_prior_votes(&self, timestamp: u64) -> u64 {
        // Binary search: returns FIRST entry with ts <= target
        // This is wrong when multiple checkpoints share a timestamp
        let mut lo = 0usize;
        let mut hi = self.checkpoints.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.checkpoints[mid].timestamp <= timestamp {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            0
        } else {
            self.checkpoints[lo - 1].votes
        }
    }
}

fn main() {
    let mut ledger = VoteLedger::default();
    ledger.write_checkpoint(100, 50);
    // BUG: second checkpoint at same timestamp not merged
    ledger.write_checkpoint(100, 75);
    ledger.write_checkpoint(200, 100);
    
    // Attacker flash-loans: transfer in, checkpoint, transfer out, checkpoint
    // All in block 100. First checkpoint has 50, second has 0 (after transfer out)
    // But get_prior_votes(100) returns 75 (last entry) not 50 (first)
    // Actually with this buggy binary search, it returns last <=, which is 75
    // The real bug: if binary search returned FIRST, attacker gets stale power
    
    // Demonstration: voter had 50, then 75 in same block
    // Query at block 100 should see final state (75) but if search
    // had returned first match, would see 50 — stale power exploit
    assert_eq!(ledger.checkpoints.len(), 3); // should be 2
    println!("vulnerable: checkpoints={}", ledger.checkpoints.len());
}
