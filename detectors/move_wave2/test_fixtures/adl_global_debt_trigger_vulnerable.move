// fixture: positive — adl_global_debt_trigger (VULNERABLE)
// Bug: trigger_adl checks total_debt (global) instead of per-group debt.
module lending::adl {
    struct Protocol has key {
        total_debt: u128,
        adl_threshold: u128,
    }

    public fun trigger_adl(
        protocol: &Protocol,
        group_id: u64,
        position_id: u64,
    ): bool {
        // Bug: uses total_debt (global) — healthy positions in other groups
        // may be force-liquidated due to unrelated group's debt.
        if (protocol.total_debt > protocol.adl_threshold) {
            // liquidate position
            true
        } else {
            false
        }
    }
}
