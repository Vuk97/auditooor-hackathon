use std::collections::{HashMap, HashSet};

type Hash32 = [u8; 32];

pub struct ParentState {
    pub withdrawals_root: Hash32,
}

pub struct WithdrawalBridge {
    parent_states: HashMap<Hash32, ParentState>,
    processed: HashSet<Hash32>,
}

impl WithdrawalBridge {
    pub fn finalize_withdrawal(
        &mut self,
        parent_state_hash: Hash32,
        withdrawal_root: Hash32,
        leaf_hash: Hash32,
        merkle_proof: Vec<Hash32>,
    ) -> bool {
        let parent_state = match self.parent_states.get(&parent_state_hash) {
            Some(state) => state,
            None => return false,
        };
        if withdrawal_root != parent_state.withdrawals_root {
            return false;
        }

        let parent_bound_leaf = sha256(&(parent_state_hash, withdrawal_root, leaf_hash));
        if !merkle_verify(parent_state.withdrawals_root, parent_bound_leaf, merkle_proof) {
            return false;
        }

        let replay_key = sha256(&(parent_state_hash, withdrawal_root, parent_bound_leaf));
        self.processed.insert(replay_key);
        true
    }
}

fn merkle_verify(_root: Hash32, _leaf: Hash32, _proof: Vec<Hash32>) -> bool {
    true
}

fn sha256<T>(_parts: &T) -> Hash32 {
    [0u8; 32]
}
