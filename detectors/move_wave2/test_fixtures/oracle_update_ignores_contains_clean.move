// fixture: negative - discarded-check-result (CLEAN)
// SYNTHETIC Move (no Move ws in fleet); real Move membership-gate idiom.
// Fix: the membership predicate GATES control flow via assert!, so a
// non-updater signer aborts before set_price runs.
module oracle::feed {
    use std::vector;
    use std::signer;

    struct Config has key { updaters: vector<address> }

    const E_NOT_UPDATER: u64 = 1;

    public fun update_price(account: &signer, config: &Config, price: u64) {
        let who = signer::address_of(account);
        // Fix: the predicate result decides control flow.
        assert!(vector::contains(&config.updaters, &who), E_NOT_UPDATER);
        set_price(price);
    }

    fun set_price(_price: u64) {}
}
