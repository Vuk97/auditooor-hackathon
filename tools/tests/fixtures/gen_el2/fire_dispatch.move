module app::dispatch {
    use aptos_std::table;
    // A Move dispatch table add with no contains/exists check.
    // GEN-EL2 must FIRE (router-map, no-add-collision-require).
    struct Registry has key { dispatch_table: table::Table<u64, address> }

    public fun register(reg: &mut Registry, sel: u64, target: address) {
        table::add(&mut reg.dispatch_table, sel, target);
    }
}
