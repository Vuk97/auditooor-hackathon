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
    // BUG: Uses only action_hash as key, causing collision for duplicate actions
    // in the same proposal. Second identical action reverts, DoS'ing the proposal.
    queued_actions: HashMap<FixedBytes<32>, bool>,
}

impl ProposalQueue {
    fn new() -> Self {
        Self {
            queued_actions: HashMap::new(),
        }
    }

    fn queue_proposal(&mut self, _proposal_id: U256, actions: Vec<Action>) -> Result<(), String> {
        for action in actions.iter() {
            let action_hash = action.hash();
            // BUG: Collision when same action appears twice in one proposal
            if self.queued_actions.contains_key(&action_hash) {
                return Err("Action already queued".to_string());
            }
            self.queued_actions.insert(action_hash, true);
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
    
    // Duplicate actions cause queue to fail
    let actions = vec![action.clone(), action.clone()];
    
    let result = queue.queue_proposal(proposal_id, actions);
    assert!(result.is_err(), "Vulnerable: Duplicate actions should cause failure");
    println!("Vulnerable: Proposal with repeated actions cannot be executed (DoS)");
}