use std::collections::HashMap;

/// Vulnerable version: uses manipulable slot0 for reallocation decisions
pub struct PoolState {
    pub slot0: Slot0,
}

#[derive(Clone, Copy)]
pub struct Slot0 {
    pub sqrt_price_x96: u128,
    pub tick: i32,
}

pub struct Position {
    pub tick_lower: i32,
    pub tick_upper: i32,
    pub liquidity: u128,
}

pub struct LpManager {
    pub pool: PoolState,
    pub positions: HashMap<u64, Position>,
}

impl LpManager {
    pub fn new(pool: PoolState) -> Self {
        Self {
            pool,
            positions: HashMap::new(),
        }
    }

    /// VULNERABLE: Uses slot0.tick directly, which is manipulable via flash loan/swap
    pub fn should_reallocate(&self, position_id: u64) -> bool {
        let position = match self.positions.get(&position_id) {
            Some(p) => p,
            None => return false,
        };
        
        // DIRECT USE OF MANIPULABLE slot0.tick
        let current_tick = self.pool.slot0.tick;
        
        // Position is out of range if current tick is outside bounds
        current_tick < position.tick_lower || current_tick >= position.tick_upper
    }

    /// VULNERABLE: Reallocation decision based on slot0.sqrtPriceX96
    pub fn reallocate(&mut self, position_id: u64) -> Option<(i32, i32)> {
        // BUG: Uses slot0 for reallocation trigger
        if !self.should_reallocate(position_id) {
            return None;
        }
        
        // BUG: Uses slot0.sqrt_price_x96 to calculate new range
        let current_tick = self.pool.slot0.tick;
        let new_lower = current_tick - 100;
        let new_upper = current_tick + 100;
        
        Some((new_lower, new_upper))
    }

    /// Additional vulnerable path: direct slot0 read in rebalance logic
    pub fn check_and_rebalance(&mut self, position_id: u64) -> bool {
        let position = match self.positions.get(&position_id) {
            Some(p) => p,
            None => return false,
        };
        
        // VULNERABLE: Multiple direct slot0 accesses for decision
        let slot0_tick = self.pool.slot0.tick;
        let slot0_sqrt_price = self.pool.slot0.sqrt_price_x96;
        
        // Attacker can manipulate both values in single block
        let out_of_range = slot0_tick < position.tick_lower || slot0_tick >= position.tick_upper;
        
        if out_of_range {
            // Force reallocation to "centered" position around manipulated price
            let _new_lower = slot0_tick - 100;
            let _new_upper = slot0_tick + 100;
            true
        } else {
            false
        }
    }
}

fn main() {
    let slot0 = Slot0 { sqrt_price_x96: 1u128 << 96, tick: 0 };
    let pool = PoolState { slot0 };
    let mut manager = LpManager::new(pool);
    manager.positions.insert(1, Position { tick_lower: -50, tick_upper: 50, liquidity: 1000 });
    
    // Attacker manipulates slot0.tick to 200 via flash loan swap
    // Position appears out of range, forces unnecessary reallocation
    assert_eq!(manager.should_reallocate(1), false);
    println!("Vulnerable: slot0-based reallocation decision");
}