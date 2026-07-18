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

    /// INTENDED: Only callable through governance proposal execution
    /// BUG: No access control - any external caller can invoke this directly
    pub fn update_impact(&mut self, service_id: u64, new_impact: u64) {
        // Missing: self.governance.assert_governance_caller();
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
    // Attacker can call directly without governance authorization
    nft.update_impact(42, 9999);
}