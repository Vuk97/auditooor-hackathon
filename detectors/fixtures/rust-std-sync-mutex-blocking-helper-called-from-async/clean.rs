// CLEAN fixture: three safe variants that SHOULD NOT fire.
//
// 1. The sync helper is wrapped in spawn_blocking before being called from async.
// 2. The async fn uses tokio::sync::Mutex (async lock, .lock().await).
// 3. The async fn has no .await points (never yields, so blocking is bounded).

use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

struct PeerBook {
    peers: Vec<String>,
}

impl PeerBook {
    fn all_peers(&self) -> Vec<String> {
        self.peers.clone()
    }
}

// --- Variant 1: spawn_blocking wraps the sync locking helper ---

fn sync_lock_helper(book: &Arc<Mutex<PeerBook>>) -> Vec<String> {
    book.lock().expect("unpoisoned").all_peers()
}

pub async fn safe_async_with_spawn_blocking(book: Arc<Mutex<PeerBook>>) {
    let peers = tokio::task::spawn_blocking(move || {
        sync_lock_helper(&book)
    })
    .await
    .expect("spawn_blocking ok");
    consume_peers(peers).await;
}

// --- Variant 2: async fn uses tokio::sync::Mutex (.lock().await is safe) ---

fn pure_compute(peers: Vec<String>) -> usize {
    peers.len()
}

pub async fn safe_async_with_tokio_mutex(book: Arc<AsyncMutex<PeerBook>>) {
    let guard = book.lock().await; // async lock - does not block thread
    let count = pure_compute(guard.peers.clone());
    drop(guard); // explicit drop before next await
    log_count(count).await;
}

// --- Variant 3: async fn calls sync helper but never .awaits ---
// (no executor interleaving possible, so no concurrency hazard)

fn another_sync_helper(book: &Arc<Mutex<PeerBook>>) -> usize {
    book.lock().expect("unpoisoned").peers.len()
}

pub async fn async_fn_no_await(book: Arc<Mutex<PeerBook>>) {
    // No .await in this body => not flagged
    let _n = another_sync_helper(&book);
}

async fn consume_peers(_peers: Vec<String>) {}
async fn log_count(_n: usize) {}
