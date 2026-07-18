use std::cmp::Ordering;

#[derive(Clone, Debug)]
struct Checkpoint {
    ts: u64,
    votes: u128,
}

struct VotingEscrow {
    checkpoints: Vec<Vec<Checkpoint>>,
}

impl VotingEscrow {
    fn get_past_votes(&self, account: usize, ts: u64) -> u128 {
        let cps = &self.checkpoints[account];
        if cps.is_empty() {
            return 0;
        }
        
        // Binary search that handles duplicates by finding the LAST occurrence
        let mut left = 0usize;
        let mut right = cps.len();
        
        while left < right {
            let mid = left + (right - left) / 2;
            match cps[mid].ts.cmp(&ts) {
                Ordering::Less => left = mid + 1,
                Ordering::Greater => right = mid,
                Ordering::Equal => {
                    // Find the last checkpoint with this exact timestamp
                    left = mid + 1;
                }
            }
        }
        
        // left is now the first index > ts, so we want left - 1
        if left == 0 {
            return 0;
        }
        
        // Verify we found the rightmost occurrence by scanning back
        let mut idx = left - 1;
        while idx > 0 && cps[idx - 1].ts == ts {
            idx -= 1;
        }
        // Actually we want the LAST one, so find rightmost equal
        let mut final_idx = left - 1;
        while final_idx + 1 < cps.len() && cps[final_idx + 1].ts == ts {
            final_idx += 1;
        }
        
        cps[final_idx].votes
    }
    
    fn new() -> Self {
        Self { checkpoints: vec![vec![]] }
    }
}

fn main() {
    let mut ve = VotingEscrow::new();
    ve.checkpoints[0] = vec![
        Checkpoint { ts: 100, votes: 100 },
        Checkpoint { ts: 200, votes: 200 },
        Checkpoint { ts: 300, votes: 300 },
        Checkpoint { ts: 300, votes: 400 }, // duplicate timestamp, higher votes
        Checkpoint { ts: 400, votes: 500 },
    ];
    
    assert_eq!(ve.get_past_votes(0, 300), 400); // should return 400, the last at ts=300
    assert_eq!(ve.get_past_votes(0, 350), 400); // should return 400
}