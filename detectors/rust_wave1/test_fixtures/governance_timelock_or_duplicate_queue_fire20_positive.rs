use std::collections::HashMap;

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
    pub action: Action,
}

pub struct Governor {
    pub queued_transactions: HashMap<u64, QueuedAction>,
}

impl Governor {
    pub fn queue_transaction(&mut self, target: u64, value: u128, signature: u128, data: u128) {
        let tx_hash = hash(&(target, value, signature, data));
        self.queued_transactions.insert(
            tx_hash,
            QueuedAction {
                ready_at: current_time() + 10,
                action: Action {
                    target,
                    value,
                    signature,
                    data,
                },
            },
        );
    }

    pub fn execute_proposal(&mut self, proposal_id: u64) -> Result<(), &'static str> {
        let queued = self
            .queued_transactions
            .get(&proposal_id)
            .ok_or("missing proposal")?;
        queued.action.execute()
    }
}

pub struct Htlc;

impl Htlc {
    pub fn commit(timelock: u64, amount: u128) {
        persist_commit(timelock, amount);
    }

    pub fn add_lock(expiration: u64, recipient: u64) {
        persist_lock(expiration, recipient);
    }
}

fn current_time() -> u64 {
    100
}

fn hash(_input: &(u64, u128, u128, u128)) -> u64 {
    0
}

fn persist_commit(_timelock: u64, _amount: u128) {}

fn persist_lock(_expiration: u64, _recipient: u64) {}
