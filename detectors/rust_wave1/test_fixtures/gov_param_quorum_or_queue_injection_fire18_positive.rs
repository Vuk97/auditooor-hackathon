use std::collections::HashMap;

#[derive(Clone)]
pub struct Action {
    pub target: [u8; 20],
    pub value: u64,
    pub data: Vec<u8>,
}

impl Action {
    pub fn hash(&self) -> [u8; 32] {
        [self.target[0]; 32]
    }

    pub fn execute(&self) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct ProposalVotes {
    pub for_votes: u64,
    pub against_votes: u64,
    pub abstain_votes: u64,
}

pub struct QueuedOperation {
    pub ready_at: u64,
    pub action: Action,
}

pub struct Fire18Governor {
    pub total_supply: u64,
    pub quorum_numerator: u64,
    pub quorum_denominator: u64,
    pub queued_actions: HashMap<[u8; 32], bool>,
    pub scheduled: HashMap<u64, QueuedOperation>,
}

impl Fire18Governor {
    pub fn count_votes(&self, votes: u64) -> u64 {
        integer_sqrt(votes)
    }

    pub fn quorum(&self) -> u64 {
        self.total_supply
            .checked_mul(self.quorum_numerator)
            .and_then(|value| value.checked_div(self.quorum_denominator))
            .unwrap_or(0)
    }

    pub fn quorum_reached(&self, proposal: &ProposalVotes) -> bool {
        let participation = proposal.against_votes + proposal.abstain_votes;
        participation >= self.quorum()
    }

    pub fn queue_proposal_actions(
        &mut self,
        proposal_id: u64,
        actions: Vec<Action>,
    ) -> Result<(), &'static str> {
        for action in actions.iter() {
            let action_hash = action.hash();
            if self.queued_actions.contains_key(&action_hash) {
                return Err("action already queued");
            }
            self.queued_actions.insert(action_hash, true);
        }
        let _ = proposal_id;
        Ok(())
    }

    pub fn schedule_timelock_operation(
        &mut self,
        proposal_id: u64,
        action: Action,
        now: u64,
        delay: u64,
    ) {
        let ready_at = now + delay;
        let operation = QueuedOperation { ready_at, action };
        if now >= ready_at {
            self.scheduled.insert(proposal_id, operation);
        } else {
            self.scheduled.insert(proposal_id, operation);
        }
    }

    pub fn execute_proposal_action(&mut self, proposal_id: u64) -> Result<(), &'static str> {
        let operation = self.scheduled.get(&proposal_id).ok_or("missing operation")?;
        operation.action.execute()
    }
}

fn integer_sqrt(input: u64) -> u64 {
    if input == 0 {
        return 0;
    }
    let mut x = input;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + input / x) / 2;
    }
    x
}
