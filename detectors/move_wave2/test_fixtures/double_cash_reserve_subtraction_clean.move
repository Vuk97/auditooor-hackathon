// fixture: negative — double_cash_reserve_subtraction (CLEAN)
// Fix: cash_reserve subtracted only once.
module lending::limits {
    struct Pool has key {
        total_deposits: u64,
        cash_reserve: u64,
        max_deposits: u64,
    }

    public fun deposit_limit_breached(pool: &Pool, new_amount: u64): bool {
        // Fix: single subtraction of cash_reserve
        let available_capacity = pool.max_deposits - pool.total_deposits + pool.cash_reserve;
        new_amount > available_capacity
    }
}
