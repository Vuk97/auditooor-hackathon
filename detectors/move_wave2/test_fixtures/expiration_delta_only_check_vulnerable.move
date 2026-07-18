// fixture: positive — expiration_delta_only_check (VULNERABLE)
// Bug: only validates delta, not current + delta vs MAX_EXPIRATION.
module locks::expiry {
    const MAX_EXPIRATION: u64 = 365 * 24 * 3600; // 1 year in seconds

    public fun extend_expiration(
        current_expiry: u64,
        delta: u64,
    ): u64 {
        // Bug: only checks delta <= MAX_EXPIRATION, not (current + delta)
        assert!(delta <= MAX_EXPIRATION, 0);
        current_expiry + delta
    }
}
