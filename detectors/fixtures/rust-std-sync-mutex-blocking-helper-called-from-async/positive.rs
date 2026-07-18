// POSITIVE fixture: async fn calls a sync helper that internally acquires
// a std::sync::Mutex guard, without spawn_blocking.
// The detector SHOULD fire on `async_caller`.

use std::sync::{Arc, Mutex};

struct AddressBook {
    entries: Vec<String>,
}

impl AddressBook {
    fn cacheable(&self) -> Vec<String> {
        self.entries.clone()
    }
}

/// Sync helper: acquires the mutex guard directly.
fn cacheable_peers(address_book: &Arc<Mutex<AddressBook>>) -> Vec<String> {
    // TODO: use spawn_blocking() here, if needed to handle address book mutex load
    address_book
        .lock()
        .expect("unexpected panic in previous thread")
        .cacheable()
}

/// Async caller: calls the sync helper directly (blocks tokio thread).
pub async fn async_caller(address_book: Arc<Mutex<AddressBook>>) {
    let peers = cacheable_peers(&address_book); // <-- blocks executor thread
    do_async_io(peers).await;
}

async fn do_async_io(_peers: Vec<String>) {
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
}
