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
        
        // BUG: Standard binary search - returns arbitrary match on duplicates
        let mut low = 0;
        let mut high = cps.len() - 1;
        
        while low <= high {
            let mid = (low + high) / 2;
            match cps[mid].ts.cmp(&ts) {
                Ordering::Less => low = mid + 1,
                Ordering::Greater => {
                    if mid == 0 { break; }
                    high = mid - 1;
                }
                Ordering::Equal => {
                    // BUG: Returns immediately on first match - could be any duplicate
                    return cps[mid].votes;
                }
            }
        }
        
        // Fallback: return nearest lower checkpoint (also buggy for duplicates)
        if low == 0 {
            return 0;
        }
        cps[low - 1].votes
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
    
    // BUG: May return 300 or 400 arbitrarily depending on search path
    let result = ve.get_past_votes(0, 300);
    println!("Got: {}", result); // unpredictable!
    
    // Attacker can exploit: if they get 300 instead of 400, they have less voting power recorded
    // This affects governance proposals, reward calculations, etc.
}