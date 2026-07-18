use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickRange {
    pub tick_lower: i32,
    pub tick_upper: i32,
}

#[derive(Clone, Debug)]
pub struct Vault {
    pub id: u64,
    pub tick_range: TickRange,
    pub total_liquidity: u128,
}

#[derive(Clone, Debug)]
pub struct Position {
    pub owner: [u8; 32],
    pub tick_range: TickRange,
    pub liquidity: u128,
}

pub struct LiquidityManager {
    pub vaults: HashMap<u64, Vault>,
    pub positions: HashMap<u64, Vec<Position>>,
    pub next_position_id: u64,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidTickRange,
    VaultNotFound,
}

impl LiquidityManager {
    pub fn new() -> Self {
        Self {
            vaults: HashMap::new(),
            positions: HashMap::new(),
            next_position_id: 1,
        }
    }

    pub fn create_vault(&mut self, id: u64, tick_lower: i32, tick_upper: i32) -> Result<(), Error> {
        if tick_lower >= tick_upper {
            return Err(Error::InvalidTickRange);
        }
        self.vaults.insert(id, Vault {
            id,
            tick_range: TickRange { tick_lower, tick_upper },
            total_liquidity: 0,
        });
        Ok(())
    }

    /// VULNERABLE: Accepts user-provided tick range without validating against vault
    pub fn deposit_fixed(
        &mut self,
        vault_id: u64,
        owner: [u8; 32],
        tick_lower: i32,
        tick_upper: i32,
        liquidity: u128,
    ) -> Result<u64, Error> {
        let _vault = self.vaults.get(&vault_id).ok_or(Error::VaultNotFound)?;
        
        // BUG: No validation that tick_lower/tick_upper match vault.tick_range!
        // User can provide ANY valid tick range, even outside vault's range.
        // This allows skipping premium payment while still receiving fee shares.
        
        if tick_lower >= tick_upper {
            return Err(Error::InvalidTickRange);
        }

        let pos_id = self.next_position_id;
        self.next_position_id += 1;

        let position = Position {
            owner,
            tick_range: TickRange { tick_lower, tick_upper },
            liquidity,
        };

        self.positions.entry(vault_id).or_default().push(position);
        
        // Update vault total liquidity (includes out-of-range positions)
        let vault = self.vaults.get_mut(&vault_id).unwrap();
        vault.total_liquidity += liquidity;

        Ok(pos_id)
    }

    pub fn collect_fees(&self, vault_id: u64, _position_id: u64) -> Option<u128> {
        // BUG: Fee distribution doesn't check if position is in vault's range
        // Out-of-range positions still get fee share proportional to liquidity
        let vault = self.vaults.get(&vault_id)?;
        let positions = self.positions.get(&vault_id)?;
        
        // All positions get fees, even those outside vault range
        let total_liquidity: u128 = positions.iter().map(|p| p.liquidity).sum();
        
        Some(total_liquidity * 100 / vault.total_liquidity)
    }
}

fn main() {
    let mut manager = LiquidityManager::new();
    manager.create_vault(1, -100, 100).unwrap();
    
    let owner = [0u8; 32];
    
    // Normal deposit in range
    let pos1 = manager.deposit_fixed(1, owner, -100, 100, 1000).unwrap();
    println!("In-range position {} created", pos1);
    
    // EXPLOIT: Deposit OUTSIDE vault range - no premium paid, but gets fee share!
    let pos2 = manager.deposit_fixed(1, owner, -500, -200, 500).unwrap();
    println!("Out-of-range position {} created (BUG: no premium, gets fees!)", pos2);
    
    // Even narrower range within vault range but not matching
    let pos3 = manager.deposit_fixed(1, owner, -50, 50, 200).unwrap();
    println!("Sub-range position {} created (BUG: different risk profile!)", pos3);
    
    println!("Vault total liquidity: {}", manager.vaults.get(&1).unwrap().total_liquidity);
}