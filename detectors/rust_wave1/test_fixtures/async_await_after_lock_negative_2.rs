// NEGATIVE: the only .await is the lock() itself — the guard assignment
// is `lock().await` which is the safe pattern recommended by tokio docs.
// No separate .await after the guard is live.

use tokio::sync::Mutex;
use std::sync::Arc;

struct Counter {
    value: Arc<Mutex<i64>>,
}

impl Counter {
    // SAFE: .await is on the lock() itself, not on something after
    pub async fn increment(&self) -> i64 {
        let mut guard = self.value.lock().await;
        *guard += 1;
        *guard
        // guard dropped at end of fn, no further .await
    }

    // SAFE: non-async fn — no executor involved
    pub fn sync_read(&self) -> i64 {
        // This would block, but it's not async
        0
    }
}
