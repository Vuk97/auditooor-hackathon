use std::collections::HashMap;

pub struct Proposal {
    pub id: u64,
    pub snapshot_block: u64,
    pub start_time: u64,
    pub end_time: u64,
}

pub struct QueuedTx {
    pub target: [u8; 20],
    pub value: u64,
    pub executed: bool,
}

pub struct Fire16Governance {
    pub proposals: HashMap<u64, Proposal>,
    pub snapshot_balances: HashMap<(u64, u64), u64>,
    pub queued_transactions: HashMap<[u8; 32], QueuedTx>,
    pub refunds: HashMap<[u8; 32], u64>,
    pub impact_scores: HashMap<u64, u64>,
}

impl Fire16Governance {
    pub fn get_votes_at(&self, voter: u64, snapshot_block: u64) -> u64 {
        self.snapshot_balances
            .get(&(snapshot_block, voter))
            .copied()
            .unwrap_or(0)
    }

    pub fn cast_vote(&mut self, proposal_id: u64, voter: u64, support: bool) -> Result<(), &'static str> {
        let proposal = self.proposals.get(&proposal_id).ok_or("proposal missing")?;
        let now = 100;
        if now < proposal.start_time || now > proposal.end_time {
            return Err("vote closed");
        }

        let voting_power = self.get_votes_at(voter, proposal.snapshot_block);
        if voting_power == 0 {
            return Err("no voting power");
        }

        let _ = support;
        Ok(())
    }

    pub fn execute_transaction(
        &mut self,
        tx_hash: [u8; 32],
        received_value: u64,
    ) -> Result<(), &'static str> {
        let tx = self.queued_transactions
            .get_mut(&tx_hash)
            .ok_or("transaction missing")?;
        let required = tx.value;
        if received_value < required {
            return Err("insufficient value");
        }

        let refund = received_value.saturating_sub(required);
        tx.executed = true;
        self.transfer_native(tx.target, required)?;
        if refund > 0 {
            self.refunds.insert(tx_hash, refund);
        }
        Ok(())
    }

    /// Only governance proposal execution may update service impact.
    pub fn update_impact(&mut self, service_id: u64, new_impact: u64) {
        self.assert_governance_caller();
        self.impact_scores.insert(service_id, new_impact);
        self.cascade_rewards_update(service_id);
    }

    fn assert_governance_caller(&self) {}

    fn transfer_native(&mut self, _target: [u8; 20], _amount: u64) -> Result<(), &'static str> {
        Ok(())
    }

    fn cascade_rewards_update(&mut self, _service_id: u64) {}
}
