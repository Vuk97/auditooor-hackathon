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
        if !self.parent_states.contains_key(&parent_state_hash) {
            return false;
        }

        if !merkle_verify(withdrawal_root, leaf_hash, merkle_proof) {
            return false;
        }

        let replay_key = sha256(&(withdrawal_root, leaf_hash));
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
