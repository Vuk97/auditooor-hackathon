use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: u64,
    pub snapshot_block: u64,
    pub start_time: u64,
    pub end_time: u64,
}

pub struct GovernanceState {
    pub proposals: HashMap<u64, Proposal>,
    pub balances: HashMap<(u64, u64), u64>, // (block, user) -> balance
    pub current_balances: HashMap<u64, u64>, // user -> current balance
}

impl GovernanceState {
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            balances: HashMap::new(),
            current_balances: HashMap::new(),
        }
    }

    pub fn set_balance_at(&mut self, user: u64, block: u64, amount: u64) {
        self.balances.insert((block, user), amount);
    }

    pub fn set_current_balance(&mut self, user: u64, amount: u64) {
        self.current_balances.insert(user, amount);
    }

    pub fn add_proposal(&mut self, proposal: Proposal) {
        self.proposals.insert(proposal.id, proposal);
    }

    /// Get voting power at a specific block (snapshot)
    pub fn get_votes_at(&self, user: u64, block: u64) -> u64 {
        self.balances.get(&(block, user)).copied().unwrap_or(0)
    }

    /// Get current voting power (BROKEN: ignores snapshot)
    pub fn get_current_votes(&self, user: u64) -> u64 {
        self.current_balances.get(&user).copied().unwrap_or(0)
    }

    /// Cast vote using CURRENT balance instead of snapshot
    pub fn cast_vote(&mut self, proposal_id: u64, voter: u64, support: bool) -> Result<(), &'static str> {
        let proposal = self.proposals.get(&proposal_id).ok_or("Proposal not found")?;
        
        let current_time = 100; // mock block time
        if current_time < proposal.start_time {
            return Err("Voting not started");
        }
        if current_time > proposal.end_time {
            return Err("Voting ended");
        }

        // BUG: Uses current balance instead of snapshot balance at proposal.snapshot_block
        let voting_power = self.get_current_votes(voter);
        // CORRECT would be: let voting_power = self.get_votes_at(voter, proposal.snapshot_block);
        
        if voting_power == 0 {
            return Err("No voting power");
        }

        // Record vote with current (wrong) voting power
        println!("Vote cast: proposal={}, voter={}, support={}, power={}", 
                 proposal_id, voter, support, voting_power);
        
        Ok(())
    }
}

fn main() {
    let mut state = GovernanceState::new();
    
    state.set_balance_at(1, 10, 1000); // user 1 had 1000 at block 10
    state.set_current_balance(1, 500);  // user 1 now has 500
    
    state.add_proposal(Proposal {
        id: 1,
        snapshot_block: 10,
        start_time: 50,
        end_time: 150,
    });
    
    // BUG: Uses 500 (current) instead of 1000 (snapshot)
    // Attacker could buy after proposal, vote, then sell
    state.cast_vote(1, 1, true).unwrap();
}