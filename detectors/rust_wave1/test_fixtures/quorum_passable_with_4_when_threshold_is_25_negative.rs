use std::collections::HashMap;

pub struct TokenGovernor {
    pub total_supply: u64,
    pub proposals: HashMap<u64, Proposal>,
}

#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: u64,
    pub for_votes: u64,
    pub against_votes: u64,
    pub abstain_votes: u64,
    pub quorum_threshold_bps: u16, // basis points, e.g. 2500 = 25%
}

impl TokenGovernor {
    pub fn new(total_supply: u64) -> Self {
        Self {
            total_supply,
            proposals: HashMap::new(),
        }
    }

    pub fn create_proposal(&mut self, id: u64, quorum_threshold_bps: u16) {
        self.proposals.insert(id, Proposal {
            id,
            for_votes: 0,
            against_votes: 0,
            abstain_votes: 0,
            quorum_threshold_bps,
        });
    }

    pub fn cast_vote(&mut self, proposal_id: u64, voter_power: u64, vote_type: VoteType) {
        let proposal = self.proposals.get_mut(&proposal_id).unwrap();
        match vote_type {
            VoteType::For => proposal.for_votes += voter_power,
            VoteType::Against => proposal.against_votes += voter_power,
            VoteType::Abstain => proposal.abstain_votes += voter_power,
        }
    }

    /// CORRECT: quorum is checked against total_supply, not just cast votes
    pub fn quorum_reached(&self, proposal_id: u64) -> bool {
        let proposal = self.proposals.get(&proposal_id).unwrap();
        let quorum_needed = (self.total_supply as u128)
            .checked_mul(proposal.quorum_threshold_bps as u128)
            .unwrap()
            .checked_div(10000)
            .unwrap() as u64;
        proposal.for_votes >= quorum_needed
    }

    pub fn execute_proposal(&self, proposal_id: u64) -> Result<(), &'static str> {
        if !self.quorum_reached(proposal_id) {
            return Err("quorum not reached");
        }
        let proposal = self.proposals.get(&proposal_id).unwrap();
        if proposal.against_votes >= proposal.for_votes {
            return Err("proposal defeated");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum VoteType {
    For,
    Against,
    Abstain,
}

fn main() {
    let mut gov = TokenGovernor::new(1_000_000);
    gov.create_proposal(1, 2500); // 25% quorum required = 250,000

    // Attacker with 40% can pass (correct behavior: needs 25% of total)
    gov.cast_vote(1, 400_000, VoteType::For);
    assert!(gov.quorum_reached(1));

    // Attacker with only 4% cannot pass (correct behavior)
    let mut gov2 = TokenGovernor::new(1_000_000);
    gov2.create_proposal(2, 2500);
    gov2.cast_vote(2, 40_000, VoteType::For);
    assert!(!gov2.quorum_reached(2));

    println!("clean: quorum correctly checked against total_supply");
}