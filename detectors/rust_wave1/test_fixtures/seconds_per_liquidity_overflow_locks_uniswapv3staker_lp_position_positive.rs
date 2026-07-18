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
    seconds_per_liquidity_cumulative_x128: u128, // VULNERABLE: uses u128 instead of u256
}

#[derive(Clone, Copy)]
struct Slot0 {
    tick: i32,
}

// VULNERABLE: Uses u128 arithmetic that overflows
fn get_seconds_per_liquidity_inside_x128(
    pool: &PoolState,
    tick_lower: i32,
    tick_upper: i32,
) -> u128 {
    let lower = pool.ticks.get(&tick_lower).unwrap();
    let upper = pool.ticks.get(&tick_upper).unwrap();
    
    let current_tick = pool.slot0.tick;
    
    // VULNERABLE: Direct u128 arithmetic wraps on overflow
    if current_tick < tick_lower {
        lower.seconds_per_liquidity_outside_x128 - upper.seconds_per_liquidity_outside_x128
    } else if current_tick < tick_upper {
        // VULNERABLE: This subtraction can underflow when liquidity is tiny and time is long
        // seconds_per_liquidity_cumulative can exceed lower+upper outside values
        pool.seconds_per_liquidity_cumulative_x128
            - lower.seconds_per_liquidity_outside_x128
            - upper.seconds_per_liquidity_outside_x128
    } else {
        upper.seconds_per_liquidity_outside_x128 - lower.seconds_per_liquidity_outside_x128
    }
}

fn unstake(
    pool: &PoolState,
    tick_lower: i32,
    tick_upper: i32,
    position: &Position,
) -> u128 {
    let current = get_seconds_per_liquidity_inside_x128(pool, tick_lower, tick_upper);
    
    // VULNERABLE: checked_sub fails when overflow occurred in get_seconds_per_liquidity_inside_x128
    // The overflowed (wrapped) value is now LESS than position.seconds_per_liquidity_inside_last_x128
    // causing this to return None and locking the position
    let reward_growth = current.checked_sub(position.seconds_per_liquidity_inside_last_x128)
        .expect("seconds_per_liquidity overflow locked position");
    
    reward_growth
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
    
    // Simulate long time elapsed with tiny liquidity: seconds_per_liquidity = seconds / liquidity
    // With liquidity=1 and many seconds, this overflows u128
    let huge_seconds_per_liquidity = u128::MAX; // Would be even larger in reality
    
    let pool = PoolState {
        ticks,
        slot0: Slot0 { tick: 0 },
        seconds_per_liquidity_cumulative_x128: huge_seconds_per_liquidity,
    };
    
    let position = Position {
        liquidity: 1, // Tiny liquidity causes huge seconds_per_liquidity
        seconds_per_liquidity_inside_last_x128: 0,
    };
    
    // This will panic due to checked_sub failing after overflow
    let result = std::panic::catch_unwind(|| {
        unstake(&pool, -100, 100, &position)
    });
    
    match result {
        Ok(_) => println!("Unexpected success"),
        Err(_) => println!("Vulnerable version: position locked due to overflow"),
    }
}