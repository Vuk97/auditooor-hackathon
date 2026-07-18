use std::collections::HashMap;

/// Uniswap V3 position manager with per-pair liquidity tracking.
/// Clean version: each pair's liquidity is isolated by pair_id.
struct UniswapPool {
    // (tick_lower, tick_upper) -> pair_id -> liquidity
    positions: HashMap<(i32, i32), HashMap<u64, u128>>,
}

struct Pair {
    pair_id: u64,
    tick_lower: i32,
    tick_upper: i32,
    liquidity: u128,
}

impl UniswapPool {
    fn new() -> Self {
        Self {
            positions: HashMap::new(),
        }
    }

    /// Mint liquidity for a specific pair into a tick range.
    fn mint(&mut self, pair: &Pair, liquidity: u128) {
        let pair_positions = self
            .positions
            .entry((pair.tick_lower, pair.tick_upper))
            .or_default();
        *pair_positions.entry(pair.pair_id).or_insert(0) += liquidity;
    }

    /// Burn liquidity ONLY for the calling pair, never touching others.
    fn burn(&mut self, pair: &Pair, liquidity: u128) -> Result<(), &'static str> {
        let pair_positions = self
            .positions
            .get_mut(&(pair.tick_lower, pair.tick_upper))
            .ok_or("No positions in range")?;
        
        let own_liquidity = pair_positions
            .get_mut(&pair.pair_id)
            .ok_or("No liquidity for this pair")?;
        
        if *own_liquidity < liquidity {
            return Err("Insufficient pair liquidity");
        }
        
        *own_liquidity -= liquidity;
        if *own_liquidity == 0 {
            pair_positions.remove(&pair.pair_id);
        }
        
        Ok(())
    }

    /// Reallocate: burn own liquidity, then mint new position.
    fn reallocate(&mut self, pair: &mut Pair, new_lower: i32, new_upper: i32, new_liquidity: u128) -> Result<(), &'static str> {
        // Only burn what this pair owns
        self.burn(pair, pair.liquidity)?;
        
        pair.tick_lower = new_lower;
        pair.tick_upper = new_upper;
        pair.liquidity = new_liquidity;
        
        self.mint(pair, new_liquidity);
        Ok(())
    }
}

fn main() {
    let mut pool = UniswapPool::new();
    let mut pair_a = Pair { pair_id: 1, tick_lower: 100, tick_upper: 200, liquidity: 1000 };
    let mut pair_b = Pair { pair_id: 2, tick_lower: 100, tick_upper: 200, liquidity: 500 };
    
    pool.mint(&pair_a, 1000);
    pool.mint(&pair_b, 500);
    
    // Pair A can only reallocate its own 1000, cannot touch pair B's 500
    pool.reallocate(&mut pair_a, 150, 250, 800).unwrap();
    
    // Verify pair B's liquidity is untouched
    let b_liq = pool.positions.get(&(100, 200)).unwrap().get(&2).unwrap();
    assert_eq!(*b_liq, 500);
    println!("Clean: pair isolation preserved");
}