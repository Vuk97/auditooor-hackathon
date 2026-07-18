use std::collections::HashSet;

/// Selector for changeCouncil function
const CHANGE_COUNCIL_SELECTOR: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

/// Represents a governance action with target and full calldata
#[derive(Clone, Debug)]
struct Action {
    target: [u8; 20],
    value: u64,
    calldata: Vec<u8>,
}

/// Governance contract with proper veto protection
struct Governance {
    council: [u8; 20],
    proposals: Vec<Vec<Action>>,
}

impl Governance {
    fn new(council: [u8; 20]) -> Self {
        Self {
            council,
            proposals: Vec::new(),
        }
    }

    /// Create a new proposal
    fn propose(&mut self, actions: Vec<Action>) -> usize {
        let id = self.proposals.len();
        self.proposals.push(actions);
        id
    }

    /// Check if calldata contains changeCouncil selector at ANY depth
    /// Proper implementation: recursively decode and check inner calls
    fn contains_change_council_recursive(calldata: &[u8]) -> bool {
        // Check direct selector match
        if calldata.len() >= 4 && calldata[0..4] == CHANGE_COUNCIL_SELECTOR {
            return true;
        }
        
        // Check for encoded sub-calls (simplified: look for embedded selectors)
        // In production, this would properly ABI-decode and recurse
        for window in calldata.windows(4) {
            if window == CHANGE_COUNCIL_SELECTOR {
                return true;
            }
        }
        false
    }

    /// Veto a proposal — properly protects council by checking all nested calls
    fn veto(&self, proposal_id: usize, caller: [u8; 20]) -> Result<(), &'static str> {
        if caller != self.council {
            return Err("Only council can veto");
        }
        
        let proposal = self.proposals.get(proposal_id)
            .ok_or("Invalid proposal")?;
        
        for action in proposal {
            // DEEP inspection: recursively check for changeCouncil at any level
            if Self::contains_change_council_recursive(&action.calldata) {
                return Err("Cannot veto council change proposal");
            }
        }
        
        // Proceed with veto
        Ok(())
    }
}

/// Wrapper contract that encodes inner calls
struct CallWrapper;

impl CallWrapper {
    fn encode_multicall(actions: Vec<Action>) -> Vec<u8> {
        let mut result = vec![0x99, 0x88, 0x77, 0x66]; // multicall selector
        for action in actions {
            result.extend_from_slice(&action.target);
            result.extend_from_slice(&action.value.to_le_bytes());
            result.extend_from_slice(&(action.calldata.len() as u32).to_le_bytes());
            result.extend_from_slice(&action.calldata);
        }
        result
    }
}

fn main() {
    let council = [1u8; 20];
    let mut gov = Governance::new(council);
    
    // Even if wrapped, the deep check catches it
    let inner_action = Action {
        target: [2u8; 20],
        value: 0,
        calldata: CHANGE_COUNCIL_SELECTOR.to_vec(),
    };
    let wrapped = CallWrapper::encode_multicall(vec![inner_action]);
    
    let proposal = vec![Action {
        target: [3u8; 20],
        value: 0,
        calldata: wrapped,
    }];
    
    let pid = gov.propose(proposal);
    
    // This correctly fails because deep check finds changeCouncil
    assert!(gov.veto(pid, council).is_err());
    println!("Clean: Veto protection works correctly");
}