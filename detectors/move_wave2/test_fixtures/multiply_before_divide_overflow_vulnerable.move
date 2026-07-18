// fixture: positive — multiply_before_divide_overflow (VULNERABLE)
// Bug: (reward * PRECISION) overflows u128 before the division.
module lending::reward_manager {
    const PRECISION: u128 = 1_000_000_000;

    public fun update_pool_reward_manager(
        reward: u128,
        elapsed_seconds: u128,
        total_liquidity: u128,
    ): u128 {
        // Bug: reward * PRECISION may overflow u128 before / total_liquidity
        let reward_per_unit = reward * PRECISION / total_liquidity;
        reward_per_unit * elapsed_seconds
    }
}
