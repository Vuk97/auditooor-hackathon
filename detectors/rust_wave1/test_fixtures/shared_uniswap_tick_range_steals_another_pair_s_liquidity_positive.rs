use std::collections::HashMap;

/// Uniswap V3 position manager with SHARED liquidity tracking.
/// Vulnerable version: liquidity is commingled by tick range only,
/// no per-pair isolation. Any pair can burn the total liquidity.
struct UniswapPool {
    // (tick_lower, tick_upper) -> total liquidity (shared across all pairs!)
    positions: HashMap<(i32, i32), u128>,
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

    /// Mint liquidity into a tick range (shared pool).
    fn mint(&mut self, pair: &Pair, liquidity: u128) {
        *self
            .positions
            .entry((pair.tick_lower, pair.tick_upper))
            .or_insert(0) += liquidity;
    }

    /// Burn liquidity from the SHARED pool for this tick range.
    /// BUG: No verification that caller owns this liquidity!
    fn burn(&mut self, tick_lower: i32, tick_upper: i32, liquidity: u128) -> Result<(), &'static str> {
        let total = self
            .positions
            .get_mut(&(tick_lower, tick_upper))
            .ok_or("No positions in range")?;
        
        if *total < liquidity {
            return Err("Insufficient total liquidity");
        }
        
        *total -= liquidity;
        Ok(())
    }

    /// Reallocate: burn from shared pool, then mint new position.
    /// VULNERABILITY: pair_b can call this with pair_a's tick range and
    /// burn all liquidity, effectively stealing pair_a's share.
    fn reallocate(&mut self, pair: &mut Pair, new_lower: i32, new_upper: i32, new_liquidity: u128) -> Result<(), &'static str> {
        // BUG: burns from shared pool without checking pair ownership
        self.burn(pair.tick_lower, pair.tick_upper, pair.liquidity)?;
        
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
    
    // Pair B maliciously reallocates with pair A's liquidity amount
    // This burns 1500 from shared pool (1000 + 500), stealing pair A's 1000
    // Then mints 500 for pair B in new range
    let stolen = pair_a.liquidity + pair_b.liquidity; // 1500 total
    pair_b.liquidity = stolen; // malicious: claim we want to burn all
    pool.reallocate(&mut pair_b, 300, 400, 500).unwrap();
    
    // Pair A's liquidity is gone from original range
    let remaining = pool.positions.get(&(100, 200)).unwrap_or(&0);
    assert_eq!(*remaining, 0); // Stolen!
    println!("Vulnerable: pair A's liquidity stolen by pair B");
}