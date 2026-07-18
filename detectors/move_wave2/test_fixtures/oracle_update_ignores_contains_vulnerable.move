// fixture: positive - discarded-check-result (VULNERABLE)
// SYNTHETIC Move (no Move ws in fleet); real Move membership-gate idiom.
// Corpus anchor: Typus (Sui Move) CRITICAL ~$3.44M, Oct-2025 - a membership/
// auth predicate whose boolean result was not acted upon.
//
// Bug: `vector::contains(&config.updaters, &who)` returns a bool that is
// SILENTLY DISCARDED (bare expression statement). The updater-allowlist gate
// never enforces anything, so ANY signer can push an oracle price.
module oracle::feed {
    use std::vector;
    use std::signer;

    struct Config has key { updaters: vector<address> }

    public fun update_price(account: &signer, config: &Config, price: u64) {
        let who = signer::address_of(account);
        // Bug: predicate result discarded - the gate is a no-op.
        vector::contains(&config.updaters, &who);
        set_price(price);
    }

    fun set_price(_price: u64) {}
}
