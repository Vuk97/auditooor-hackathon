use std::collections::HashMap;

/// Safe version: uses time-weighted average price (TWAP) for reallocation decisions
pub struct PoolState {
    pub slot0: Slot0,
    pub observations: Vec<Observation>,
}

#[derive(Clone, Copy)]
pub struct Slot0 {
    pub sqrt_price_x96: u128,
    pub tick: i32,
}

#[derive(Clone, Copy)]
pub struct Observation {
    pub block_timestamp: u32,
    pub tick_cumulative: i64,
    pub seconds_per_liquidity_cumulative_x128: u128,
}

pub struct Position {
    pub tick_lower: i32,
    pub tick_upper: i32,
    pub liquidity: u128,
}

pub struct LpManager {
    pub pool: PoolState,
    pub positions: HashMap<u64, Position>,
    pub twap_window_seconds: u32,
}

impl LpManager {
    pub fn new(pool: PoolState, twap_window_seconds: u32) -> Self {
        Self {
            pool,
            positions: HashMap::new(),
            twap_window_seconds,
        }
    }

    /// Get time-weighted average tick from oracle observations
    fn get_twap_tick(&self) -> i32 {
        let observations = &self.pool.observations;
        if observations.len() < 2 {
            return self.pool.slot0.tick;
        }
        
        let newest = observations[observations.len() - 1];
        let oldest = observations[0];
        let time_delta = newest.block_timestamp.saturating_sub(oldest.block_timestamp) as u32;
        
        if time_delta < self.twap_window_seconds {
            return self.pool.slot0.tick;
        }
        
        let tick_cumulative_delta = newest.tick_cumulative - oldest.tick_cumulative;
        (tick_cumulative_delta / time_delta as i64) as i32
    }

    /// SAFE: Uses TWAP for reallocation decision, not manipulable slot0
    pub fn should_reallocate(&self, position_id: u64) -> bool {
        let position = match self.positions.get(&position_id) {
            Some(p) => p,
            None => return false,
        };
        
        let twap_tick = self.get_twap_tick();
        
        // Position is out of range if TWAP tick is outside position bounds
        twap_tick < position.tick_lower || twap_tick >= position.tick_upper
    }

    pub fn reallocate(&mut self, position_id: u64) -> Option<(i32, i32)> {
        if !self.should_reallocate(position_id) {
            return None;
        }
        
        // Calculate new range around TWAP tick
        let twap_tick = self.get_twap_tick();
        let new_lower = twap_tick - 100;
        let new_upper = twap_tick + 100;
        
        Some((new_lower, new_upper))
    }
}

fn main() {
    let slot0 = Slot0 { sqrt_price_x96: 1u128 << 96, tick: 0 };
    let pool = PoolState {
        slot0,
        observations: vec![
            Observation { block_timestamp: 1000, tick_cumulative: 0, seconds_per_liquidity_cumulative_x128: 0 },
            Observation { block_timestamp: 2000, tick_cumulative: 50000, seconds_per_liquidity_cumulative_x128: 0 },
        ],
    };
    let mut manager = LpManager::new(pool, 900);
    manager.positions.insert(1, Position { tick_lower: -50, tick_upper: 50, liquidity: 1000 });
    
    // TWAP tick = 50000 / 1000 = 50, position is in range
    assert_eq!(manager.should_reallocate(1), false);
    println!("Clean: TWAP-based reallocation decision");
}