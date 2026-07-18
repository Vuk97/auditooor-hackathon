// NEGATIVE: guard is explicitly dropped before .await — no deadlock.

use tokio::sync::Mutex;
use std::sync::Arc;

struct Service {
    state: Arc<Mutex<u64>>,
}

impl Service {
    // SAFE: guard dropped before awaiting
    pub async fn safe_update(&self) -> u64 {
        let value = {
            let mut guard = self.state.lock().await;
            *guard += 1;
            *guard
            // guard dropped here when the block closes
        };
        // No lock held at this point
        let result = fetch_data().await;
        result + value
    }
}

async fn fetch_data() -> u64 {
    42
}
