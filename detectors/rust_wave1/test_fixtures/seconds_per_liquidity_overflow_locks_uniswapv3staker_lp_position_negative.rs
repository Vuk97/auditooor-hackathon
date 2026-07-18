use std::time::{SystemTime, UNIX_EPOCH};

/// Fixed-point Q128.128 representation for seconds per liquidity
const Q128: u128 = 1u128 << 128;

#[derive(Clone, Debug)]
struct TickInfo {
    seconds_per_liquidity_outside_x128: u128,
    tick_cumulative_outside: i64,
    initialized: bool,
}

#[derive(Clone, Debug)]
struct Position {
    liquidity: u128,
    seconds_per_liquidity_inside_last_x128: u128,
}

struct PoolState {
    ticks: std::collections::BTreeMap<i32, TickInfo>,
    slot0: Slot0,
    seconds_per_liquidity_cumulative_x128: u256,
}

#[derive(Clone, Copy)]
struct Slot0 {
    tick: i32,
}

// Use u256 from alloy_primitives for safe arithmetic
use alloy_primitives::U256;

fn get_seconds_per_liquidity_inside_x128(
    pool: &PoolState,
    tick_lower: i32,
    tick_upper: i32,
    position: &Position,
) -> Option<u128> {
    let lower = pool.ticks.get(&tick_lower)?;
    let upper = pool.ticks.get(&tick_upper)?;
    
    let current_tick = pool.slot0.tick;
    
    // Calculate using U256 to prevent overflow
    let seconds_per_liquidity_cumulative = U256::from(pool.seconds_per_liquidity_cumulative_x128);
    
    let (seconds_inside_x128, _) = if current_tick < tick_lower {
        // Both outside
        let lower_outside = U256::from(lower.seconds_per_liquidity_outside_x128);
        let upper_outside = U256::from(upper.seconds_per_liquidity_outside_x128);
        let diff = upper_outside.checked_sub(lower_outside)?;
        (diff, 0u128)
    } else if current_tick < tick_upper {
        // Inside range
        let lower_outside = U256::from(lower.seconds_per_liquidity_outside_x128);
        let upper_outside = U256::from(upper.seconds_per_liquidity_outside_x128);
        let sum = lower_outside.checked_add(upper_outside)?;
        let diff = seconds_per_liquidity_cumulative.checked_sub(sum)?;
        (diff, 0u128)
    } else {
        // Both outside (above)
        let lower_outside = U256::from(lower.seconds_per_liquidity_outside_x128);
        let upper_outside = U256::from(upper.seconds_per_liquidity_outside_x128);
        let diff = lower_outside.checked_sub(upper_outside)?;
        (diff, 0u128)
    };
    
    // Safe conversion with overflow check
    if seconds_inside_x128 > U256::from(u128::MAX) {
        return None;
    }
    
    Some(seconds_inside_x128.low_u128())
}

fn can_unstake(
    pool: &PoolState,
    tick_lower: i32,
    tick_upper: i32,
    position: &Position,
) -> bool {
    let current = match get_seconds_per_liquidity_inside_x128(pool, tick_lower, tick_upper, position) {
        Some(v) => v,
        None => return false, // Graceful handling on overflow
    };
    
    // Safe subtraction with overflow protection
    let _reward_growth = match current.checked_sub(position.seconds_per_liquidity_inside_last_x128) {
        Some(v) => v,
        None => return false, // Would have underflowed - position locked in vulnerable version
    };
    
    true
}

fn main() {
    let mut ticks = std::collections::BTreeMap::new();
    ticks.insert(-100, TickInfo {
        seconds_per_liquidity_outside_x128: 0,
        tick_cumulative_outside: 0,
        initialized: true,
    });
    ticks.insert(100, TickInfo {
        seconds_per_liquidity_outside_x128: 0,
        tick_cumulative_outside: 0,
        initialized: true,
    });
    
    let pool = PoolState {
        ticks,
        slot0: Slot0 { tick: 0 },
        seconds_per_liquidity_cumulative_x128: U256::from(Q128) * U256::from(1000000u128),
    };
    
    let position = Position {
        liquidity: 1, // Tiny liquidity
        seconds_per_liquidity_inside_last_x128: 0,
    };
    
    assert!(can_unstake(&pool, -100, 100, &position));
    println!("Clean version: unstake succeeded with overflow protection");
}