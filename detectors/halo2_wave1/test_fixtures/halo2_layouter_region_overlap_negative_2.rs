// Negative #2: non-halo2 file. Detector should bail at is_halo2_file().
pub fn run() -> u64 {
    let layouter = FakeLayouter::default();
    layouter.assign_region(|| "shared", |r| r.do_thing());
    layouter.assign_region(|| "shared", |r| r.do_thing());
    42
}
