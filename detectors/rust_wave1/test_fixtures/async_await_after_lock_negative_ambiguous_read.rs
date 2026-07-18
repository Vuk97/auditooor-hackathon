// NEGATIVE: `.read()` here is a no-arg accessor on an atomic/cell-like type,
// NOT an RwLock read guard. There is NO blocking-lock type in evidence (no
// tokio::sync / std::sync / parking_lot import, no RwLock/Mutex annotation),
// so the ambiguous `.read()` receiver must NOT be flagged as a held guard.

struct Sensor {
    register: VolatileCell<u64>,
}

impl Sensor {
    pub async fn sample_then_send(&self) -> bool {
        // `read()` on a VolatileCell returns a value by copy; no guard is held
        let snapshot = self.register.read();
        send(snapshot).await
    }
}

async fn send(_v: u64) -> bool {
    true
}
