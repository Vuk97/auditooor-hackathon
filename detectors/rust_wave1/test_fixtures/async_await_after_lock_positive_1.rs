// POSITIVE: async fn holds a Mutex guard across .await — deadlock risk.
// The guard `guard` from `state.lock()` is still live when `fetch_data().await`
// is called.  On tokio's cooperative scheduler this parks the executor thread
// while the lock is held, potentially deadlocking.

use tokio::sync::Mutex;
use std::sync::Arc;

struct Service {
    state: Arc<Mutex<u64>>,
}

impl Service {
    // VULN: guard held across .await
    pub async fn update_and_fetch(&self) -> u64 {
        let mut guard = self.state.lock().await;
        *guard += 1;
        // .await here while guard is still live
        let result = fetch_data().await;
        *guard = result;
        result
    }
}

async fn fetch_data() -> u64 {
    42
}
