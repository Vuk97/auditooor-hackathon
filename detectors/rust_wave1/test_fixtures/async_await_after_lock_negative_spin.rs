// NEGATIVE: a spin::Mutex is a busy-spin (non-yielding) lock. Holding its
// guard across .await does NOT park the tokio executor in the deadlock sense
// this detector targets, so it must NOT be flagged.

use spin::Mutex;
use std::sync::Arc;

struct SpinService {
    state: Arc<spin::Mutex<u64>>,
}

impl SpinService {
    // SAFE for this detector: spin lock does not yield to the async executor
    pub async fn update_and_fetch(&self) -> u64 {
        let mut guard = self.state.lock();
        *guard += 1;
        let result = fetch_data().await;
        *guard = result;
        result
    }
}

async fn fetch_data() -> u64 {
    42
}
