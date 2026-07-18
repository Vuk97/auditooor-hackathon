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
    pub expires_at: u64,
    pub action: Action,
    pub executed: bool,
}

pub struct Fire18Governor {
    pub total_supply: u64,
    pub quorum_numerator: u64,
    pub quorum_denominator: u64,
    pub queued_actions: HashMap<(u64, u64), bool>,
    pub scheduled: HashMap<u64, QueuedOperation>,
}

impl Fire18Governor {
    pub fn count_votes(&self, votes: u64) -> u64 {
        integer_sqrt(votes)
    }

    pub fn quorum(&self) -> u64 {
        let sqrt_total_supply = integer_sqrt(self.total_supply);
        sqrt_total_supply
            .checked_mul(self.quorum_numerator)
            .and_then(|value| value.checked_div(self.quorum_denominator))
            .unwrap_or(0)
    }

    pub fn quorum_reached(&self, proposal: &ProposalVotes) -> bool {
        let participation = proposal.for_votes + proposal.abstain_votes;
        participation >= self.quorum()
    }

    pub fn queue_proposal_actions(
        &mut self,
        proposal_id: u64,
        actions: Vec<Action>,
    ) -> Result<(), &'static str> {
        for (idx, _action) in actions.iter().enumerate() {
            let key = (proposal_id, idx as u64);
            if self.queued_actions.contains_key(&key) {
                return Err("action already queued");
            }
            self.queued_actions.insert(key, true);
        }
        Ok(())
    }

    pub fn schedule_timelock_operation(
        &mut self,
        proposal_id: u64,
        action: Action,
        now: u64,
        delay: u64,
        ttl: u64,
    ) {
        let ready_at = now + delay;
        let expires_at = ready_at + ttl;
        let operation = QueuedOperation {
            ready_at,
            expires_at,
            action,
            executed: false,
        };
        self.scheduled.insert(proposal_id, operation);
    }

    pub fn execute_proposal_action(&mut self, proposal_id: u64, now: u64) -> Result<(), &'static str> {
        self.assert_authorized_executor();
        let operation = self.scheduled.get_mut(&proposal_id).ok_or("missing operation")?;
        if now < operation.ready_at || now > operation.expires_at || operation.executed {
            return Err("operation not executable");
        }
        operation.executed = true;
        operation.action.execute()
    }

    fn assert_authorized_executor(&self) {}
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
