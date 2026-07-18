// fixture: negative — reward_pool_close_before_materialization (CLEAN)
// Fix: materialize borrower rewards before refunding owner.
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
        // Fix: materialize rewards for all borrowers first
        materialize_rewards(pool);
        // Then refund remaining balance to owner
        let remaining = pool.balance;
        pool.balance = 0;
        coin::transfer(remaining, pool.owner);
    }

    fun materialize_rewards(pool: &mut RewardPool) {
        // distribute accrued rewards to borrowers
    }
}
