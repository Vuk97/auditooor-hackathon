// fixture: negative — adl_global_debt_trigger (CLEAN)
// Fix: use per-group debt for the ADL trigger.
module lending::adl {
    struct Group has key {
        group_debt: u128,
        adl_threshold: u128,
    }

    public fun trigger_adl(
        group: &Group,
        group_id: u64,
        position_id: u64,
    ): bool {
        // Fix: check per-group debt — only affects the specific group
        if (group.group_debt > group.adl_threshold) {
            true
        } else {
            false
        }
    }
}
