// fixture: SYNTHETIC Move Coin<T> value-conservation (split/join desync). M1.
// Real Move idiom: a Coin resource carries a `value: u64` field; `split` must
// obey resource-linearity sum(parts) == whole. VULNERABLE `split_bad` creates a
// part carrying `amount` but omits the paired `whole.value -= amount` join, so
// value is MINTED (sum(parts) > whole). CLEAN `split` keeps the join. There is
// NO real Move ws in the fleet - this is a faithful synthetic clean+vulnerable pair.
module coins::purse {
    struct Coin<phantom T> has store {
        value: u64,
    }

    /// VULNERABLE: creates a `amount`-valued part but never decrements the whole.
    public fun split_bad<T>(whole: &mut Coin<T>, amount: u64): Coin<T> {
        // BUG: paired `whole.value = whole.value - amount;` join MISSING (L14 below).
        Coin<T> { value: amount }
    }

    /// CLEAN: whole is decremented by `amount` (paired join) before the part packs.
    public fun split<T>(whole: &mut Coin<T>, amount: u64): Coin<T> {
        whole.value = whole.value - amount;
        Coin<T> { value: amount }
    }

    /// Authorized minter has NO source Coin - must NOT be read as a broken split.
    public fun mint<T>(amount: u64): Coin<T> {
        Coin<T> { value: amount }
    }
}
