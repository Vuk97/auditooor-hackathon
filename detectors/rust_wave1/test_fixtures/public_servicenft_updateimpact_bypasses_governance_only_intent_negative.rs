use std::collections::HashMap;

pub struct ServiceNft {
    pub impact_scores: HashMap<u64, u64>,
    pub governance: Governance,
}

pub struct Governance {
    pub authorized_proposal: Option<u64>,
}

impl ServiceNft {
    pub fn new() -> Self {
        Self {
            impact_scores: HashMap::new(),
            governance: Governance { authorized_proposal: None },
        }
    }

    /// Only callable through governance proposal execution
    pub fn update_impact(&mut self, service_id: u64, new_impact: u64) {
        self.governance.assert_governance_caller();
        self.impact_scores.insert(service_id, new_impact);
        self.cascade_rewards_update(service_id);
    }

    fn cascade_rewards_update(&mut self, service_id: u64) {
        // Internal reward recalculation logic
        let _ = service_id;
    }
}

impl Governance {
    fn assert_governance_caller(&self) {
        assert!(
            self.authorized_proposal.is_some(),
            "Caller is not governance"
        );
    }
}

fn main() {
    let mut nft = ServiceNft::new();
    // Simulated governance call path
    nft.governance.authorized_proposal = Some(1);
    nft.update_impact(42, 100);
}