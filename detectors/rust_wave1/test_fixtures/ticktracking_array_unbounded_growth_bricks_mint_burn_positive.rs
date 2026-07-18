use std::vec::Vec;

/// Vulnerable: unbounded tick tracking array growth
pub struct LiquidityPosition {
    pub tick_lower: i32,
    pub tick_upper: i32,
}

pub struct TickEntry {
    pub tick: i32,
    pub timestamp: u64,
}

pub struct LiquidityMining {
    /// tickTracking_ pushes entry on EVERY in/out of range crossing
    /// No pruning, no bounds check — grows unbounded
    tick_tracking: Vec<TickEntry>,
}

impl LiquidityMining {
    pub fn new() -> Self {
        Self {
            tick_tracking: Vec::new(),
        }
    }

    /// Called on every tick crossing — no bounds check!
    pub fn update_tick_tracking(&mut self, current_tick: i32, current_time: u64) {
        // VULNERABLE: unconditional push, no pruning, no max size
        self.tick_tracking.push(TickEntry {
            tick: current_tick,
            timestamp: current_time,
        });
    }

    /// Iterates entire tickTracking_ — O(n) where n grows unbounded
    pub fn mint(&self, position: &LiquidityPosition) -> Result<(), &'static str> {
        // Must validate position against all tick history — gas cost grows forever
        for entry in &self.tick_tracking {
            if entry.tick >= position.tick_lower && entry.tick <= position.tick_upper {
                // validation logic
            }
        }
        Ok(())
    }

    /// Same unbounded iteration
    pub fn burn(&self, position: &LiquidityPosition) -> Result<(), &'static str> {
        for entry in &self.tick_tracking {
            if entry.tick >= position.tick_lower && entry.tick <= position.tick_upper {
                // validation logic
            }
        }
        Ok(())
    }

    pub fn is_in_range(&self, _tick: i32) -> bool {
        // Called frequently, triggers tickTracking_ push on transitions
        true
    }
}

fn main() {
    let mut lm = LiquidityMining::new();
    // Attacker dust-swaps to force repeated range crossings
    for i in 0..100_000 {
        lm.update_tick_tracking(i as i32, i as u64);
    }
    // mint/burn now extremely expensive, eventually OOG
    let _ = lm.mint(&LiquidityPosition { tick_lower: 0, tick_upper: 100 });
}