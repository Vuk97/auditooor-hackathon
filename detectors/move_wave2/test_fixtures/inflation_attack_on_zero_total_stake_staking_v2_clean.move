module staking::thapt_pool {
    const INITIAL_SHARES: u64 = 1_000_000;

    struct Pool has key {
        total_stake: u64,
        total_shares: u64,
        fee_bps: u64,
    }

    public entry fun stake_thAPT_v2(pool: &mut Pool, amount: u64): u64 {
        let fee = amount * pool.fee_bps / 10000;
        let net_thapt = amount - fee;
        let stapt_shares = if (pool.total_stake == 0) {
            net_thapt * INITIAL_SHARES
        } else {
            net_thapt * pool.total_shares / pool.total_stake
        };
        pool.total_stake = pool.total_stake + net_thapt;
        pool.total_shares = pool.total_shares + stapt_shares;
        stapt_shares
    }
}
