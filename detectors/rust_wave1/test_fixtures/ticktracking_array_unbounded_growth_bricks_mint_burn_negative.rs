use std::collections::VecDeque;

/// Clean: bounded tick tracking with pruning/ring buffer
pub struct LiquidityPosition {
    pub tick_lower: i32,
    pub tick_upper: i32,
}

pub struct TickEntry {
    pub tick: i32,
    pub timestamp: u64,
}

const MAX_TICK_HISTORY: usize = 100;

pub struct LiquidityMining {
    tick_tracking: VecDeque<TickEntry>,
}

impl LiquidityMining {
    pub fn new() -> Self {
        Self {
            tick_tracking: VecDeque::with_capacity(MAX_TICK_HISTORY),
        }
    }

    /// Prunes old entries to maintain bounded size
    fn prune_old_entries(&mut self, current_time: u64) {
        while let Some(front) = self.tick_tracking.front() {
            if current_time.saturating_sub(front.timestamp) > 86400 {
                self.tick_tracking.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn update_tick_tracking(&mut self, current_tick: i32, current_time: u64) {
        self.prune_old_entries(current_time);
        
        if self.tick_tracking.len() >= MAX_TICK_HISTORY {
            self.tick_tracking.pop_front();
        }
        
        self.tick_tracking.push_back(TickEntry {
            tick: current_tick,
            timestamp: current_time,
        });
    }

    pub fn mint(&self, _position: &LiquidityPosition) -> Result<(), &'static str> {
        if self.tick_tracking.len() > MAX_TICK_HISTORY {
            return Err("tick tracking overflow");
        }
        Ok(())
    }

    pub fn burn(&self, _position: &LiquidityPosition) -> Result<(), &'static str> {
        if self.tick_tracking.len() > MAX_TICK_HISTORY {
            return Err("tick tracking overflow");
        }
        Ok(())
    }
}

fn main() {
    let mut lm = LiquidityMining::new();
    for i in 0..200 {
        lm.update_tick_tracking(i as i32, i as u64);
    }
    assert!(lm.mint(&LiquidityPosition { tick_lower: 0, tick_upper: 100 }).is_ok());
}