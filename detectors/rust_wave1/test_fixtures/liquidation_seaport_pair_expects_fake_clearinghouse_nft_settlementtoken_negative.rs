use std::collections::HashMap;

/// Safe ClearingHouse that validates NFT is genuine collateral, not fake
pub struct ClearingHouse {
    collateral_nft: u64,
    settlement_token: u64,
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

        // CRITICAL FIX: Validate any additional NFT in consideration is genuine
        if order.consideration.len() > 1 {
            for extra in &order.consideration[1..] {
                if !self.authorized_clearing_nfts.contains_key(extra) {
                    return Err("Invalid: unauthorized NFT in consideration");
                }
            }
        }

        Ok(())
    }

    pub fn execute_liquidation(&self, order: &Order) -> Result<(), &'static str> {
        self.validate_liquidation_order(order)?;
        // Proceed with safe liquidation
        Ok(())
    }
}

fn main() {
    let ch = ClearingHouse::new(100, 200);
    let valid_order = Order {
        offer: vec![100],
        consideration: vec![200],
    };
    assert!(ch.execute_liquidation(&valid_order).is_ok());

    let fake_nft = 999;
    let malicious_order = Order {
        offer: vec![100],
        consideration: vec![200, fake_nft],
    };
    assert!(ch.execute_liquidation(&malicious_order).is_err());
}