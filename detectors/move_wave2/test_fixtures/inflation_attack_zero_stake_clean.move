// fixture: negative — inflation_attack_zero_stake (CLEAN)
// Fix: guard against total_stake == 0 with a fixed initial ratio.
module staking::pool {
    const INITIAL_SHARES: u64 = 1_000_000;

    struct Pool has key {
        total_stake: u64,
        total_shares: u64,
    }

    public entry fun stake(pool: &mut Pool, amount: u64): u64 {
        let shares_to_mint = if (pool.total_stake == 0) {
            // Fix: use fixed initial shares for first depositor
            INITIAL_SHARES
        } else {
            amount * pool.total_shares / pool.total_stake
        };
        pool.total_stake = pool.total_stake + amount;
        pool.total_shares = pool.total_shares + shares_to_mint;
        shares_to_mint
    }
}
