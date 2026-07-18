// clean.rs - should NOT fire: all safe patterns
use std::sync::{Arc, Mutex, RwLock};

struct AddressBook {
    peers: Vec<String>,
}

impl AddressBook {
    fn recently_live_peers(&self) -> Vec<String> {
        self.peers.clone()
    }
}

struct RpcHandler {
    address_book: Arc<Mutex<AddressBook>>,
    data: Arc<RwLock<Vec<u8>>>,
    flag_sender: Arc<Mutex<tokio::sync::watch::Sender<bool>>>,
}

impl RpcHandler {
    // SAFE 1: spawn_blocking wraps the .lock() call - correct pattern from candidate_set.rs
    pub async fn get_info_fixed(&self) -> String {
        let address_book = self.address_book.clone();
        let peers = tokio::task::spawn_blocking(move || {
            address_book.lock().unwrap().recently_live_peers()
        })
        .await
        .unwrap_or_default();
        format!("peers: {}", peers.len())
    }

    // SAFE 2: sync fn - blocking is fine in a sync context
    pub fn get_info_sync(&self) -> String {
        let peers = self.address_book.lock().unwrap().recently_live_peers();
        format!("peers: {}", peers.len())
    }

    // SAFE 3: futures::lock::Mutex with .await - async-aware, does not block worker thread
    pub async fn async_mutex_usage(
        &self,
        async_lock: Arc<futures::lock::Mutex<Vec<u8>>>,
    ) -> usize {
        let guard = async_lock.lock().await;
        guard.len()
    }

    // SAFE 4: tokio::sync::Mutex with .lock().await
    pub async fn tokio_mutex_usage(
        &self,
        tok_lock: Arc<tokio::sync::Mutex<Vec<u8>>>,
    ) -> usize {
        let guard = tok_lock.lock().await;
        guard.len()
    }

    // SAFE 5: spawn_blocking wrapping RwLock.read()
    pub async fn read_data_fixed(&self) -> usize {
        let data = self.data.clone();
        tokio::task::spawn_blocking(move || {
            let guard = data.read().unwrap();
            guard.len()
        })
        .await
        .unwrap_or(0)
    }
}

// SAFE 6: .lock() in a helper closure that is itself sync (inside spawn_blocking)
pub async fn batch_update(
    lock: Arc<Mutex<Vec<u8>>>,
    items: Vec<u8>,
) {
    tokio::task::spawn_blocking(move || {
        let mut guard = lock.lock().unwrap();
        guard.extend(items);
    })
    .await
    .ok();
}

// SAFE 7: non-async fn with .lock() - acceptable blocking
fn sync_helper(lock: &Arc<Mutex<Vec<u8>>>) -> usize {
    lock.lock().unwrap().len()
}
