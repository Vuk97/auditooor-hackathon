// RU7 mutant fixture - identical to clean EXCEPT one injected index op after a
// guarded field write while the std::sync guard is still held. An OOB panic
// here poisons the Mutex -> every later lock().expect(...) panics (DoS).
use std::sync::Mutex;

struct SendStateInner {
    nonce_too_low_count: u64,
    nonce_too_high: bool,
    already_reserved: bool,
    bump_fees: bool,
    recent: Vec<u64>,
}

struct SendState {
    inner: Mutex<SendStateInner>,
}

impl SendState {
    pub fn process_send_error(&self, err: &TxManagerError) {
        let mut inner = self.inner.lock().expect("SendState mutex poisoned");
        match err {
            TxManagerError::NonceTooLow => {
                inner.nonce_too_low_count += 1;
            }
            TxManagerError::NonceTooHigh => {
                inner.nonce_too_high = true;
            }
            TxManagerError::AlreadyReserved => {
                inner.already_reserved = true;
            }
            e if e.is_retryable() => {
                inner.bump_fees = true;
                let _ = inner.recent[inner.nonce_too_low_count as usize];
            }
            _ => {}
        }
    }
}
