// fixture: positive — reward_pool_close_before_materialization (VULNERABLE)
// Bug: refunds owner before materializing borrower rewards.
module lending::rewards {
    struct RewardPool has key {
        owner: address,
        balance: u64,
        expiry: u64,
    }

    public fun close_expired_reward_pool(
        pool: &mut RewardPool,
        ctx: &mut TxContext,
    ) {
        // Bug: transfers balance to owner BEFORE materializing borrower rewards
        // Borrowers' accrued-but-not-materialized yield gets swept to owner.
        coin::transfer(pool.balance, pool.owner);
        pool.balance = 0;
        // Materialization should have happened BEFORE the refund (but doesn't)
    }
}
