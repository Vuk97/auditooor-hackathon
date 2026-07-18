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

/// Governance contract with BROKEN veto protection — only shallow check
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

    /// VULNERABLE: Only checks TOP-LEVEL selector, misses wrapped calls
    fn veto(&self, proposal_id: usize, caller: [u8; 20]) -> Result<(), &'static str> {
        if caller != self.council {
            return Err("Only council can veto");
        }
        
        let proposal = self.proposals.get(proposal_id)
            .ok_or("Invalid proposal")?;
        
        for action in proposal {
            // SHALLOW CHECK: only looks at first 4 bytes of outer calldata
            // BUG: If changeCouncil is wrapped inside a multicall/execute/forward,
            // this check passes because the outer selector is different
            if action.calldata.len() >= 4 && action.calldata[0..4] == CHANGE_COUNCIL_SELECTOR {
                return Err("Cannot veto council change proposal");
            }
        }
        
        // Proceed with veto — but we missed nested changeCouncil!
        Ok(())
    }
}

/// Wrapper contract that encodes inner calls — attacker uses this to bypass
struct CallWrapper;

impl CallWrapper {
    fn encode_multicall(actions: Vec<Action>) -> Vec<u8> {
        let mut result = vec![0x99, 0x88, 0x77, 0x66]; // multicall selector (NOT changeCouncil)
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
    
    // ATTACK: Wrap changeCouncil inside a multicall wrapper
    let inner_action = Action {
        target: [2u8; 20],
        value: 0,
        calldata: CHANGE_COUNCIL_SELECTOR.to_vec(), // the actual changeCouncil
    };
    let wrapped = CallWrapper::encode_multicall(vec![inner_action]);
    // wrapped starts with 0x99887766 (multicall), NOT 0x12345678 (changeCouncil)
    
    let proposal = vec![Action {
        target: [3u8; 20],
        value: 0,
        calldata: wrapped, // outer calldata has multicall selector
    }];
    
    let pid = gov.propose(proposal);
    
    // BUG: This succeeds when it should fail! Shallow check misses nested changeCouncil
    let result = gov.veto(pid, council);
    assert!(result.is_ok(), "Vulnerable: Veto bypassed! Council can be changed.");
    println!("Vulnerable: Selector check bypassed via wrapper");
}