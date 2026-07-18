// fixture: negative — expiration_delta_only_check (CLEAN)
// Fix: validate that (current + delta) <= MAX_EXPIRATION.
module locks::expiry {
    const MAX_EXPIRATION: u64 = 365 * 24 * 3600; // 1 year in seconds

    public fun extend_expiration(
        current_expiry: u64,
        delta: u64,
    ): u64 {
        // Fix: validate cumulative result against MAX_EXPIRATION
        assert!(current_expiry + delta <= MAX_EXPIRATION, 0);
        current_expiry + delta
    }
}
