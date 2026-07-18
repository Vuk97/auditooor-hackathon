// Negative #2: not a Halo2 file at all (no halo2 imports / Chip impl).
// Detector should yield zero hits because `is_halo2_file` returns false.
pub fn run_thing(x: u64) -> u64 {
    let region = SomeRegion::new();
    region.assign_advice("dummy_tag", x);
    region.assign_advice("dummy_other", x + 1);
    x + 42
}
