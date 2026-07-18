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

    /// BUG: quorum is checked against total cast votes, not total_supply
    /// This allows attacker with ~4% of total supply to pass 25% quorum proposal
    /// if they are the only voter (4% of total = 100% of cast votes)
    pub fn quorum_reached(&self, proposal_id: u64) -> bool {
        let proposal = self.proposals.get(&proposal_id).unwrap();
        let total_cast_votes = proposal.for_votes
            .checked_add(proposal.against_votes)
            .unwrap()
            .checked_add(proposal.abstain_votes)
            .unwrap();
        let quorum_needed = (total_cast_votes as u128)
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
    gov.create_proposal(1, 2500); // 25% quorum required = 250,000 of total

    // Attacker with only 4% of total supply can pass!
    // 40_000 / 1_000_000 = 4% of total, but 40_000 / 40_000 = 100% of cast
    // Bug: quorum calculates 25% of 40_000 cast = 10_000 needed
    // Attacker's 40_000 >= 10_000, so quorum passes!
    gov.cast_vote(1, 40_000, VoteType::For);
    assert!(gov.quorum_reached(1)); // BUG: this should be false!

    println!("vulnerable: quorum incorrectly checked against cast votes only");
}