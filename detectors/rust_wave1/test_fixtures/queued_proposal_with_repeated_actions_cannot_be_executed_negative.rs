use std::collections::HashMap;
use alloy_primitives::{Address, U256, keccak256, FixedBytes};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Action {
    target: Address,
    value: U256,
    signature: String,
    data: Vec<u8>,
}

impl Action {
    fn hash(&self) -> FixedBytes<32> {
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(self.target.as_slice());
        hasher_input.extend_from_slice(&self.value.to_be_bytes::<32>());
        hasher_input.extend_from_slice(self.signature.as_bytes());
        hasher_input.extend_from_slice(&self.data);
        keccak256(&hasher_input)
    }
}

struct ProposalQueue {
    // FIX: Use (proposal_id, action_hash) as composite key to prevent cross-proposal collisions
    // and allow duplicate actions within same proposal by using action index
    queued_actions: HashMap<(U256, u64), bool>,
}

impl ProposalQueue {
    fn new() -> Self {
        Self {
            queued_actions: HashMap::new(),
        }
    }

    fn queue_proposal(&mut self, proposal_id: U256, actions: Vec<Action>) -> Result<(), String> {
        for (idx, action) in actions.iter().enumerate() {
            let key = (proposal_id, idx as u64);
            if self.queued_actions.contains_key(&key) {
                return Err("Action already queued".to_string());
            }
            self.queued_actions.insert(key, true);
        }
        Ok(())
    }
}

fn main() {
    let mut queue = ProposalQueue::new();
    let proposal_id = U256::from(1u64);
    
    let action = Action {
        target: Address::ZERO,
        value: U256::from(100u64),
        signature: "transfer(address,uint256)".to_string(),
        data: vec![0u8; 32],
    };
    
    // Duplicate actions are allowed - queued by index
    let actions = vec![action.clone(), action.clone()];
    
    let result = queue.queue_proposal(proposal_id, actions);
    assert!(result.is_ok(), "Should queue proposal with duplicate actions");
    println!("Clean: Proposal with repeated actions queued successfully");
}