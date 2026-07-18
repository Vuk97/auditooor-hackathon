use std::collections::HashMap;

struct AuctionState {
    stage: AuctionStage,
    nft_owner: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuctionStage {
    NotStarted,
    ZoraAuction,
    OpenseaListing,
    Completed,
}

struct AuctionHooks;

impl AuctionHooks {
    // Vulnerable: hook can return false, and caller ignores the failure
    fn settle_zora_auction(&self, state: &mut AuctionState) -> bool {
        // Attacker can force this to return false via reentrancy or griefing
        if state.stage != AuctionStage::ZoraAuction {
            return false; // Failure signal
        }
        // Normal completion would set stage, but we simulate failure path
        false
    }
}

fn execute_proposal(state: &mut AuctionState, hooks: &AuctionHooks) {
    // Stage 1: Attempt Zora auction
    let _result = hooks.settle_zora_auction(state);
    
    // VULNERABLE: ignoring return value, proceeding regardless of failure
    // This allows skipping the auction stage entirely
    
    // Stage 2: Directly proceed to Opensea (auction was supposed to be required)
    proceed_to_opensea(state);
}

fn proceed_to_opensea(state: &mut AuctionState) {
    state.stage = AuctionStage::Completed;
    // Attacker now gets NFT without proper auction
}

fn main() {
    let mut state = AuctionState {
        stage: AuctionStage::ZoraAuction,
        nft_owner: "party".to_string(),
    };
    let hooks = AuctionHooks;
    
    // Attacker triggers this path
    execute_proposal(&mut state, &hooks);
    println!("Stage: {:?}", state.stage as i32);
}
