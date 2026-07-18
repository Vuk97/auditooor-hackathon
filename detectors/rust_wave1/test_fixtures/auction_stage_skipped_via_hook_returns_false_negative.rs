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
    // Clean: hook return value is properly validated, failure halts progression
    fn settle_zora_auction(&self, state: &mut AuctionState) -> Result<bool, String> {
        // Simulate auction settlement logic
        if state.stage != AuctionStage::ZoraAuction {
            return Err("Invalid stage for Zora auction".to_string());
        }
        // Auction completes successfully
        state.stage = AuctionStage::OpenseaListing;
        Ok(true)
    }
}

fn execute_proposal(state: &mut AuctionState, hooks: &AuctionHooks) -> Result<(), String> {
    // Stage 1: Attempt Zora auction
    let result = hooks.settle_zora_auction(state)?;
    
    // Clean: require success, do NOT proceed on failure
    if !result {
        return Err("Zora auction settlement failed, halting".to_string());
    }
    
    // Only proceed to Opensea if Zora succeeded
    proceed_to_opensea(state)?;
    Ok(())
}

fn proceed_to_opensea(state: &mut AuctionState) -> Result<(), String> {
    state.stage = AuctionStage::Completed;
    Ok(())
}

fn main() {
    let mut state = AuctionState {
        stage: AuctionStage::ZoraAuction,
        nft_owner: "party".to_string(),
    };
    let hooks = AuctionHooks;
    
    match execute_proposal(&mut state, &hooks) {
        Ok(()) => println!("Proposal executed successfully"),
        Err(e) => println!("Error: {}", e),
    }
}
