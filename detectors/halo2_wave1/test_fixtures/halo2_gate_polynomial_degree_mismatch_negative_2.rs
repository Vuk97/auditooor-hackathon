// Negative #2: non-halo2 file. Detector should not fire even if
// `meta.create_gate` substring appears as a non-halo2 method.
pub mod fake {
    pub struct Notebook;
    impl Notebook {
        pub fn create_gate(&self) -> u64 { 1 }
    }
}

pub fn run() -> u64 {
    fake::Notebook.create_gate() * 4
}
