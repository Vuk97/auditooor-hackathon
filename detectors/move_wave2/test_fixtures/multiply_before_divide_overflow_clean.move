// fixture: negative — multiply_before_divide_overflow (CLEAN)
// Fix: cast to u256 before multiplying to avoid overflow.
module lending::reward_manager {
    const PRECISION: u256 = 1_000_000_000;

    public fun update_pool_reward_manager(
        reward: u128,
        elapsed_seconds: u128,
        total_liquidity: u128,
    ): u128 {
        // Fix: upcast to u256 before multiply-before-divide
        let reward256 = (reward as u256);
        let reward_per_unit = (reward256 * PRECISION / (total_liquidity as u256)) as u128;
        reward_per_unit * elapsed_seconds
    }
}
