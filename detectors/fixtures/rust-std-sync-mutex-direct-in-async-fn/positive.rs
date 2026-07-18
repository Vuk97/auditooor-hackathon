// positive.rs - SHOULD fire: std::sync::Mutex.lock() directly in async fn body
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

// CASE 1: indirect call - method on Arc<Mutex<T>> that internally locks
// (represents zebra-rpc get_info / get_peer_info pattern)
impl RpcHandler {
    pub async fn get_info(&self) -> String {
        // BAD: address_book is Arc<Mutex<T>>; this method internally calls .lock()
        // on a std::sync::Mutex - blocks the tokio worker thread
        let peers = self.address_book.lock().unwrap().recently_live_peers();
        format!("peers: {}", peers.len())
    }

    // CASE 2: direct .lock() on Arc<Mutex<T>> in async fn
    // (represents zebra downloads.rs past_lookahead_limit_sender pattern)
    pub async fn update_lookahead_flag(&self, over_limit: bool) {
        // BAD: direct .lock() in async fn, no spawn_blocking
        let _ = self.flag_sender
            .lock()
            .expect("thread panicked while holding the mutex")
            .send(over_limit);
    }

    // CASE 3: RwLock .read() in async fn - also blocks
    pub async fn read_data(&self) -> usize {
        // BAD: std::sync::RwLock::read() is also blocking
        let guard = self.data.read().unwrap();
        guard.len()
    }
}

// CASE 4: top-level async fn with .lock()
pub async fn process_requests(lock: Arc<Mutex<Vec<u8>>>) -> usize {
    // BAD: direct .lock() without spawn_blocking
    let guard = lock.lock().unwrap();
    guard.len()
}
