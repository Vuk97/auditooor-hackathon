use std::collections::HashMap;
use alloy_primitives::{Address, U256};

struct Vault {
    collateral_configs: HashMap<Address, CollateralConfig>,
    user_positions: HashMap<Address, Position>,
}

struct CollateralConfig {
    shares: U256,
    total_shares: U256,
}

struct Position {
    token_id: U256,
    shares: U256,
}

struct NftCallback {
    data: Vec<u8>,
}

impl Vault {
    fn on_erc721_received(
        &mut self,
        operator: Address,
        from: Address,
        token_id: U256,
        data: NftCallback,
    ) -> [u8; 4] {
        // VULNERABLE: Update config shares first
        let shares = self.compute_shares(token_id);
        let config = self.collateral_configs.get_mut(&operator).unwrap();
        config.shares = shares; // Partial update!
        
        // VULNERABLE: External call BEFORE finalizing total_shares
        // Attacker can reenter and manipulate config based on inconsistent state
        self.safe_transfer_from(operator, from, token_id);
        
        // State finalization happens AFTER external call
        config.total_shares = config.total_shares + shares;
        
        self.user_positions.insert(from, Position {
            token_id,
            shares,
        });
        
        [0x15, 0x0b, 0x7a, 0x02] // onERC721Received selector
    }
    
    fn compute_shares(&self, token_id: U256) -> U256 {
        token_id + U256::from(100)
    }
    
    fn safe_transfer_from(&mut self, from: Address, to: Address, token_id: U256) {
        // External call triggers reentrancy before total_shares is updated
        // Attacker's onERC721Received sees config.shares set but total_shares not updated
        let _ = (from, to, token_id);
    }
}

fn main() {
    let mut vault = Vault {
        collateral_configs: HashMap::new(),
        user_positions: HashMap::new(),
    };
    vault.collateral_configs.insert(Address::ZERO, CollateralConfig {
        shares: U256::ZERO,
        total_shares: U256::ZERO,
    });
    
    let result = vault.on_erc721_received(
        Address::ZERO,
        Address::ZERO,
        U256::from(1),
        NftCallback { data: vec![] },
    );
    assert_eq!(result, [0x15, 0x0b, 0x7a, 0x02]);
}