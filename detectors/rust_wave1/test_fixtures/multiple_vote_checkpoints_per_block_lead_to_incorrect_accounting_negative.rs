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
        // CORRECT: merge with existing checkpoint if same timestamp
        if let Some(last) = self.checkpoints.last_mut() {
            if last.timestamp == timestamp {
                last.votes = votes;
                return;
            }
        }
        self.checkpoints.push(Checkpoint { timestamp, votes });
    }

    fn get_prior_votes(&self, timestamp: u64) -> u64 {
        // Binary search: find rightmost checkpoint with ts <= target
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
    ledger.write_checkpoint(100, 75); // merged, not duplicated
    ledger.write_checkpoint(200, 100);
    assert_eq!(ledger.checkpoints.len(), 2);
    assert_eq!(ledger.get_prior_votes(100), 75);
    assert_eq!(ledger.get_prior_votes(150), 75);
    println!("clean: ok");
}
