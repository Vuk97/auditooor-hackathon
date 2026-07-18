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

    /// All hosts must have voted YES for full-host-support
    pub fn has_full_host_support(&self, proposal_id: u64) -> bool {
        let Some(prop) = self.proposals.get(&proposal_id) else { return false };
        if prop.votes.len() != self.hosts.len() {
            return false;
        }
        self.hosts.iter().all(|h| {
            prop.votes.get(h) == Some(&Vote::Yes)
        })
    }

    pub fn skip_veto_delay(&self, proposal_id: u64) -> bool {
        // CORRECT: require actual unanimous support from all registered hosts
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
    
    gov.cast_vote(1, h1, Vote::Yes);
    gov.cast_vote(1, h2, Vote::Yes);
    gov.cast_vote(1, h3, Vote::Yes);
    
    assert!(gov.skip_veto_delay(1));
    assert!(gov.execute(1).is_ok());
    println!("clean: all hosts voted, veto skipped correctly");
}