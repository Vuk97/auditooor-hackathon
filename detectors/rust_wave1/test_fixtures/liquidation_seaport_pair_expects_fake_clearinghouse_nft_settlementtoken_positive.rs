use std::collections::HashMap;

/// Vulnerable ClearingHouse that accepts fake ClearingHouse NFT in consideration
pub struct ClearingHouse {
    collateral_nft: u64,
    settlement_token: u64,
    // Map exists but is never checked for additional consideration items
    authorized_clearing_nfts: HashMap<u64, bool>,
}

pub struct Order {
    pub offer: Vec<u64>,
    pub consideration: Vec<u64>,
}

impl ClearingHouse {
    pub fn new(collateral_nft: u64, settlement_token: u64) -> Self {
        let mut authorized = HashMap::new();
        authorized.insert(collateral_nft, true);
        Self {
            collateral_nft,
            settlement_token,
            authorized_clearing_nfts: authorized,
        }
    }

    pub fn validate_liquidation_order(&self, order: &Order) -> Result<(), &'static str> {
        // Ensure offer contains exactly the collateral NFT
        if order.offer.len() != 1 || order.offer[0] != self.collateral_nft {
            return Err("Invalid offer: must be collateral NFT");
        }

        // Ensure consideration has settlement token first
        if order.consideration.is_empty() || order.consideration[0] != self.settlement_token {
            return Err("Invalid consideration: first token must be settlementToken");
        }

        // BUG: No validation that additional items in consideration are authorized
        // Attacker can pass fakeClearingHouseNft as second consideration item
        // This locks collateral NFT in contract as pair expects fake NFT + settlementToken

        Ok(())
    }

    pub fn execute_liquidation(&self, order: &Order) -> Result<(), &'static str> {
        self.validate_liquidation_order(order)?;
        // Proceed with vulnerable liquidation - collateral NFT gets locked
        Ok(())
    }
}

fn main() {
    let ch = ClearingHouse::new(100, 200);
    
    // Attacker creates fake clearing house NFT
    let fake_clearing_house_nft = 999;
    
    // Malicious order: offer collateral NFT, demand settlementToken + fakeClearingHouseNft
    // No genuine buyer has fake_clearing_house_nft, so collateral NFT remains locked
    let malicious_order = Order {
        offer: vec![100],           // collateral NFT
        consideration: vec![200, fake_clearing_house_nft],  // settlementToken + fake NFT
    };
    
    // BUG: This passes validation! Collateral NFT will be locked in contract
    assert!(ch.execute_liquidation(&malicious_order).is_ok());
}