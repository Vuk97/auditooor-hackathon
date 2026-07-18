use std::collections::BTreeMap;

/// Vulnerable checkpoint implementation: APPENDS instead of overwriting same block
#[derive(Clone, Debug)]
struct Checkpoint {
    from_block: u64,
    votes: u64,
}

#[derive(Debug)]
struct VoteTracker {
    checkpoints: Vec<Checkpoint>, // APPEND-ONLY: no deduplication by block
}

impl VoteTracker {
    fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
        }
    }

    /// BUG: always pushes new checkpoint, never overwrites existing for same block
    fn write_checkpoint(&mut self, block: u64, votes: u64) {
        // VULNERABLE: append-only, no check for existing block
        self.checkpoints.push(Checkpoint {
            from_block: block,
            votes,
        });
    }

    fn get_votes_at_block(&self, block: u64) -> u64 {
        // Binary search finds FIRST match, not LAST for same block
        match self.checkpoints.binary_search_by_key(&block, |cp| cp.from_block) {
            Ok(idx) => self.checkpoints[idx].votes, // returns FIRST occurrence
            Err(idx) => self.checkpoints.get(idx.saturating_sub(1)).map(|cp| cp.votes).unwrap_or(0),
        }
    }
}

fn main() {
    let mut tracker = VoteTracker::new();
    
    // Multiple operations in same block - all appended
    tracker.write_checkpoint(100, 100); // mint
    tracker.write_checkpoint(100, 150); // transfer (appended!)
    tracker.write_checkpoint(100, 120); // burn (appended!)
    
    // BUG: binary search may return first (100) instead of last (120)
    let reported = tracker.get_votes_at_block(100);
    println!("Vulnerable: final votes = {} (expected 120, got {})", reported, reported);
    
    // Demonstrate the corruption
    assert_ne!(reported, 120, "BUG: vote accounting is incorrect!");
}
