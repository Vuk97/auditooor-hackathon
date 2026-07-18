use std::collections::{BTreeMap, BTreeSet};

pub struct Position {
    owner: u64,
}

pub struct State {
    positions: BTreeMap<u64, Position>,
}

pub struct OpenPosition {
    position_id: u64,
    owner: u64,
}

impl OpenPosition {
    pub fn position_id(&self) -> u64 {
        self.position_id
    }

    pub fn check_stateful(&self, state: &State) -> Result<(), &'static str> {
        if state.positions.contains_key(&self.position_id) {
            return Err("duplicate position id");
        }
        Ok(())
    }

    pub fn execute(&self, state: &mut State) -> Result<(), &'static str> {
        state.positions.insert(
            self.position_id,
            Position {
                owner: self.owner,
            },
        );
        Ok(())
    }
}

pub struct Transaction {
    actions: Vec<OpenPosition>,
}

pub fn deliver_transaction_guarded(
    state: &mut State,
    tx: &Transaction,
) -> Result<(), &'static str> {
    let mut reserved = BTreeSet::new();

    for action in tx.actions.iter() {
        action.check_stateful(state)?;
        if !reserved.insert(action.position_id()) {
            return Err("duplicate position id in transaction");
        }
    }

    for action in tx.actions.iter() {
        action.execute(state)?;
    }

    Ok(())
}

pub fn deliver_transaction_sequential(
    state: &mut State,
    tx: &Transaction,
) -> Result<(), &'static str> {
    for action in tx.actions.iter() {
        action.check_stateful(state)?;
        action.execute(state)?;
    }

    Ok(())
}
