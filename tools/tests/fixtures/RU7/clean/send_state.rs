// RU7 clean fixture - std::sync Mutex guard, guarded writes, NO panic op while
// holding the guard. Poison-safe. Mirrors base-azul
// crates/utilities/tx-manager/src/send_state.rs::process_send_error.
use std::sync::Mutex;

struct SendStateInner {
    nonce_too_low_count: u64,
    nonce_too_high: bool,
    already_reserved: bool,
    bump_fees: bool,
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
            }
            _ => {}
        }
    }
}
