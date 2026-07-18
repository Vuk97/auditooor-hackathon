// Negative fixture: not a Cairo file. Should produce zero findings.
// Plain Rust struct with read/write methods — no StarkNet or ZK constructs.
struct Store {
    value: u64,
}

impl Store {
    fn read(&self) -> u64 { self.value }
    fn write(&mut self, v: u64) { self.value = v; }
}

fn update(s: &mut Store) {
    let v = s.read();
    let new_v = v + 1;
    s.write(new_v);
}
