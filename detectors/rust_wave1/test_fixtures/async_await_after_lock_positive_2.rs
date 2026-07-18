// POSITIVE: parking_lot RwLock read guard held across .await.
// The `rg` read guard from `config.read()` is live when the network call awaits.

use parking_lot::RwLock;
use std::sync::Arc;

struct ConfigCache {
    config: Arc<RwLock<Vec<u8>>>,
}

impl ConfigCache {
    // VULN: read guard held across .await
    pub async fn validate_and_send(&self) -> bool {
        let rg = self.config.read();
        let payload = rg.clone();
        // .await while rg is still in scope — deadlocks if anything else tries write()
        send_payload(payload).await
    }
}

async fn send_payload(_data: Vec<u8>) -> bool {
    true
}
