// fixture: positive — double_cash_reserve_subtraction (VULNERABLE)
// Bug: cash_reserve subtracted twice in deposit_limit_breached.
module lending::limits {
    struct Pool has key {
        total_deposits: u64,
        cash_reserve: u64,
        max_deposits: u64,
    }

    public fun deposit_limit_breached(pool: &Pool, new_amount: u64): bool {
        // Bug: cash_reserve subtracted twice — understates used capacity
        let used_capacity = pool.total_deposits - pool.cash_reserve - pool.cash_reserve;
        used_capacity + new_amount > pool.max_deposits
    }
}
