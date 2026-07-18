// fixture: negative — cross_segment_cap_netting_bypass (CLEAN)
// Fix: check both per-segment AND global daily cap.
module lending::borrow {
    struct Segment has key {
        segment_cap: u64,
        segment_borrow: u64,
    }

    struct Protocol has key {
        global_daily_cap: u64,
        global_daily_borrow: u64,
    }

    public fun borrow(
        segment: &mut Segment,
        protocol: &mut Protocol,
        amount: u64,
    ) {
        // Fix: check per-segment cap
        assert!(segment.segment_borrow + amount <= segment.segment_cap, 0);
        // Fix: check global daily cap across all segments
        assert!(protocol.global_daily_borrow + amount <= protocol.global_daily_cap, 1);
        segment.segment_borrow = segment.segment_borrow + amount;
        protocol.global_daily_borrow = protocol.global_daily_borrow + amount;
    }
}
