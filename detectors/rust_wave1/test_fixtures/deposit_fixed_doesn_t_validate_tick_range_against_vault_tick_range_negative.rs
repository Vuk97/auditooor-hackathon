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
    TickRangeMismatch,
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

    /// FIXED: Validates that user-provided tick range matches vault's tick range
    pub fn deposit_fixed(
        &mut self,
        vault_id: u64,
        owner: [u8; 32],
        tick_lower: i32,
        tick_upper: i32,
        liquidity: u128,
    ) -> Result<u64, Error> {
        let vault = self.vaults.get(&vault_id).ok_or(Error::VaultNotFound)?;
        
        // CRITICAL FIX: Validate user ticks match vault ticks
        if tick_lower != vault.tick_range.tick_lower || tick_upper != vault.tick_range.tick_upper {
            return Err(Error::TickRangeMismatch);
        }
        
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
        
        // Update vault total liquidity
        let vault = self.vaults.get_mut(&vault_id).unwrap();
        vault.total_liquidity += liquidity;

        Ok(pos_id)
    }

    pub fn collect_fees(&self, vault_id: u64, position_id: u64) -> u128 {
        // Fee collection logic proportional to liquidity share
        let vault = self.vaults.get(&vault_id)?;
        let positions = self.positions.get(&vault_id)?;
        let position = positions.get(position_id as usize - 1)?;
        
        // Only positions matching vault range get fees
        if position.tick_range != vault.tick_range {
            return 0;
        }
        
        position.liquidity * 100 / vault.total_liquidity
    }
}

fn main() {
    let mut manager = LiquidityManager::new();
    manager.create_vault(1, -100, 100).unwrap();
    
    let owner = [0u8; 32];
    // Must use vault's exact tick range
    let pos_id = manager.deposit_fixed(1, owner, -100, 100, 1000).unwrap();
    println!("Position {} created", pos_id);
    
    // This would fail with TickRangeMismatch
    let result = manager.deposit_fixed(1, owner, -50, 50, 500);
    assert_eq!(result, Err(Error::TickRangeMismatch));
    println!("Correctly rejected mismatched tick range");
}