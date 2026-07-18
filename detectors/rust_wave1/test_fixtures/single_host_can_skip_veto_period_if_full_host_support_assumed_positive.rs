use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct HostId(u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Vote { Yes, No, Abstain }

pub struct Proposal {
    pub votes: HashMap<HostId, Vote>,
    pub total_hosts: u64,
}

pub struct Governance {
    proposals: HashMap<u64, Proposal>,
    hosts: Vec<HostId>,
}

impl Governance {
    pub fn new(hosts: Vec<HostId>) -> Self {
        Self {
            proposals: HashMap::new(),
            hosts,
        }
    }

    pub fn cast_vote(&mut self, proposal_id: u64, host: HostId, vote: Vote) {
        let prop = self.proposals.entry(proposal_id).or_insert(Proposal {
            votes: HashMap::new(),
            total_hosts: self.hosts.len() as u64,
        });
        prop.votes.insert(host, vote);
    }

    /// BUG: only checks that all *voting* hosts supported, not all *registered* hosts
    pub fn has_full_host_support(&self, proposal_id: u64) -> bool {
        let Some(prop) = self.proposals.get(&proposal_id) else { return false };
        if prop.votes.is_empty() {
            return false;
        }
        // VULNERABLE: checks all votes are Yes, but ignores non-voting hosts
        prop.votes.values().all(|v| *v == Vote::Yes)
    }

    pub fn skip_veto_delay(&self, proposal_id: u64) -> bool {
        // BUG: single host can vote Yes, flag is true, veto skipped
        self.has_full_host_support(proposal_id)
    }

    pub fn execute(&self, proposal_id: u64) -> Result<(), &'static str> {
        if !self.skip_veto_delay(proposal_id) {
            return Err("veto period not expired");
        }
        Ok(())
    }
}

fn main() {
    let h1 = HostId(1);
    let h2 = HostId(2);
    let h3 = HostId(3);
    let mut gov = Governance::new(vec![h1, h2, h3]);
    
    // Only one host votes, but vulnerability allows skipping veto
    gov.cast_vote(1, h1, Vote::Yes);
    
    // BUG: should be false (h2, h3 haven't voted), but returns true
    assert!(gov.has_full_host_support(1));
    assert!(gov.skip_veto_delay(1));
    assert!(gov.execute(1).is_ok());
    println!("vulnerable: single host skipped veto!");
}