// fixture: positive — cross_segment_cap_netting_bypass (VULNERABLE)
// Bug: borrow checks per-segment cap but not global daily cap.
module lending::borrow {
    struct Segment has key {
        segment_cap: u64,
        segment_borrow: u64,
    }

    public fun borrow(
        segment: &mut Segment,
        amount: u64,
    ) {
        // Bug: only per-segment check, no global daily cap
        assert!(segment.segment_borrow + amount <= segment.segment_cap, 0);
        segment.segment_borrow = segment.segment_borrow + amount;
    }
}
