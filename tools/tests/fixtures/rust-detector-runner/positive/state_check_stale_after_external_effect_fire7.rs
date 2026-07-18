use std::collections::BTreeMap;

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

pub fn deliver_transaction(state: &mut State, tx: &Transaction) -> Result<(), &'static str> {
    for action in tx.actions.iter() {
        action.check_stateful(state)?;
    }

    for action in tx.actions.iter() {
        action.execute(state)?;
    }

    Ok(())
}
