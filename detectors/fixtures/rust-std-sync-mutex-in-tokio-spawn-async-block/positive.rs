// positive.rs — SHOULD fire: std::sync::Mutex / RwLock .lock()/.read()/.write()
// called inside tokio::spawn(async ...) without .await suffix.

use std::sync::{Arc, Mutex, RwLock};

struct Downloader {
    limit_sender: Arc<Mutex<tokio::sync::watch::Sender<bool>>>,
    rw_data: Arc<RwLock<Vec<u8>>>,
}

impl Downloader {
    // Case 1: .lock() inside tokio::spawn(async move { ... }) — chained to .expect().send()
    // mirrors the real zebra pattern at downloads.rs:479
    fn download_and_verify(&self) {
        let sender = self.limit_sender.clone();
        let _task = tokio::spawn(async move {
            // It is ok to block here (maintenance hazard).
            let _ = sender.lock().expect("mutex poisoned").send(true);
        });
    }

    // Case 2: .read() inside tokio::spawn(async { ... }) (no move) — chained to .unwrap()
    fn read_data(&self) {
        let data = self.rw_data.clone();
        let _task = tokio::spawn(async {
            let guard = data.read().unwrap();
            println!("{:?}", *guard);
            // guard dropped here
        });
    }

    // Case 3: .write() inside tokio::spawn(async move { ... })
    fn write_data(&self) {
        let data = self.rw_data.clone();
        let _task = tokio::spawn(async move {
            let mut guard = data.write().unwrap();
            guard.push(42u8);
        });
    }
}
