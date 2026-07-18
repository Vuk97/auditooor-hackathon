use std::collections::HashMap;

const MIN_HTLC_DELTA: u64 = 60;

pub struct Action {
    pub target: u64,
    pub value: u128,
    pub signature: u128,
    pub data: u128,
}

impl Action {
    pub fn execute(&self) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct QueuedAction {
    pub ready_at: u64,
    pub expires_at: u64,
    pub action: Action,
    pub executed: bool,
}

pub struct Governor {
    pub queued_transactions: HashMap<(u64, u64, u64), QueuedAction>,
}

impl Governor {
    pub fn queue_transaction(
        &mut self,
        proposal_id: u64,
        action_index: u64,
        target: u64,
        value: u128,
        signature: u128,
        data: u128,
    ) {
        let tx_hash = hash(&(proposal_id, action_index, target, value, signature, data));
        let action_key = (proposal_id, action_index, tx_hash);
        self.queued_transactions.insert(
            action_key,
            QueuedAction {
                ready_at: current_time() + MIN_HTLC_DELTA,
                expires_at: current_time() + MIN_HTLC_DELTA + 300,
                action: Action {
                    target,
                    value,
                    signature,
                    data,
                },
                executed: false,
            },
        );
    }

    pub fn execute_proposal(
        &mut self,
        proposal_id: u64,
        action_index: u64,
        tx_hash: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        self.assert_authorized_executor();
        let queued = self
            .queued_transactions
            .get_mut(&(proposal_id, action_index, tx_hash))
            .ok_or("missing proposal")?;
        if now < queued.ready_at || now > queued.expires_at || queued.executed {
            return Err("not executable");
        }
        queued.executed = true;
        queued.action.execute()
    }

    fn assert_authorized_executor(&self) {}
}

pub struct Htlc;

impl Htlc {
    pub fn commit(timelock: u64, amount: u128, now: u64) -> Result<(), &'static str> {
        if timelock < now + MIN_HTLC_DELTA {
            return Err("timelock too soon");
        }
        persist_commit(timelock, amount);
        Ok(())
    }

    pub fn add_lock(expiration: u64, recipient: u64, now: u64) -> Result<(), &'static str> {
        if expiration <= now + MIN_HTLC_DELTA {
            return Err("expiration too soon");
        }
        persist_lock(expiration, recipient);
        Ok(())
    }
}

fn current_time() -> u64 {
    100
}

fn hash(_input: &(u64, u64, u64, u128, u128, u128)) -> u64 {
    0
}

fn persist_commit(_timelock: u64, _amount: u128) {}

fn persist_lock(_expiration: u64, _recipient: u64) {}
