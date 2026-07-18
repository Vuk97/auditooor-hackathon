use std::collections::BTreeMap;

/// Correct checkpoint implementation: overwrites existing checkpoint for same block/timestamp
#[derive(Clone, Debug)]
struct Checkpoint {
    from_block: u64,
    votes: u64,
}

#[derive(Debug)]
struct VoteTracker {
    checkpoints: BTreeMap<u64, Checkpoint>, // key: from_block, value: checkpoint
}

impl VoteTracker {
    fn new() -> Self {
        Self {
            checkpoints: BTreeMap::new(),
        }
    }

    /// Write checkpoint: OVERWRITES if same block exists
    fn write_checkpoint(&mut self, block: u64, votes: u64) {
        // CRITICAL FIX: overwrite existing checkpoint for same block
        self.checkpoints.insert(block, Checkpoint {
            from_block: block,
            votes,
        });
    }

    fn get_votes_at_block(&self, block: u64) -> u64 {
        self.checkpoints
            .range(..=block)
            .next_back()
            .map(|(_, cp)| cp.votes)
            .unwrap_or(0)
    }
}

fn main() {
    let mut tracker = VoteTracker::new();
    
    // Multiple operations in same block - last one wins correctly
    tracker.write_checkpoint(100, 100); // mint
    tracker.write_checkpoint(100, 150); // transfer (overwrites)
    tracker.write_checkpoint(100, 120); // burn (overwrites)
    
    assert_eq!(tracker.get_votes_at_block(100), 120);
    println!("Clean: final votes = {} (correct)", tracker.get_votes_at_block(100));
}
