// clean.rs — should NOT fire.
// Contains safe variants: spawn_blocking, tokio::sync::Mutex with .await, etc.

use std::sync::{Arc, Mutex};

struct SafeDownloader {
    limit_sender: Arc<Mutex<bool>>,
}

impl SafeDownloader {
    // Safe: spawn_blocking is the correct wrapper for std::sync::Mutex
    fn safe_blocking(&self) {
        let sender = self.limit_sender.clone();
        let _task = tokio::task::spawn_blocking(move || {
            let mut g = sender.lock().unwrap();
            *g = true;
        });
    }

    // Safe: tokio::sync::Mutex with .lock().await pattern
    fn safe_tokio_mutex(&self) {
        use std::sync::Arc;
        let m = Arc::new(tokio::sync::Mutex::new(0u32));
        let _task = tokio::spawn(async move {
            let mut g = m.lock().await;
            *g += 1;
        });
    }

    // Safe: std::sync::Mutex used OUTSIDE of async spawn (plain thread context)
    fn safe_thread_context(&self) {
        let sender = self.limit_sender.clone();
        std::thread::spawn(move || {
            let g = sender.lock().unwrap();
            println!("{:?}", g);
        });
    }

    // Safe: .read().await on tokio::sync::RwLock inside async block
    fn safe_tokio_rwlock(&self) {
        let rw = Arc::new(tokio::sync::RwLock::new(vec![1u8, 2u8]));
        let _task = tokio::spawn(async move {
            let guard = rw.read().await;
            println!("{:?}", *guard);
        });
    }
}
