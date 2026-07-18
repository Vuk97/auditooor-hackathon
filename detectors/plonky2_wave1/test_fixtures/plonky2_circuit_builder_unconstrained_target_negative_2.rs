// Negative fixture: not a Plonky2 file — no CircuitBuilder or plonky2 imports.
// Should produce zero findings.
pub fn ordinary_rust_function() {
    let secret = 42u64;
    let result = secret * 2;
    println!("result = {}", result);
}

struct SomeBuilder {
    state: Vec<u64>,
}

impl SomeBuilder {
    fn add_virtual_target(&mut self) -> u64 {
        let t = self.state.len() as u64;
        self.state.push(0);
        t
    }
    fn connect(&mut self, a: u64, b: u64) {
        assert_eq!(a, b);
    }
}
