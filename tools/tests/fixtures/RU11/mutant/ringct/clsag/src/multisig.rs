// RU11 MUTANT - behavior-changing injection over the CLEAN control.
// A `core::mem::forget` of the safety-Drop type is introduced: the receiver is
// leaked so its `Drop` never runs and the secret Scalar is NEVER zeroized
// (runs-once RAII invariant defeated). RU11 arm A must FIRE.
use zeroize::Zeroize;

struct ClsagMultisigMaskReceiver {
    buf: Arc<Mutex<Option<Scalar>>>,
}

impl ClsagMultisigMaskReceiver {
    fn recv(self) -> Option<Scalar> {
        let mut lock = self.buf.lock();
        let res = lock.take();
        (*lock).zeroize();
        res
    }

    fn leak(self) {
        // MUTATION: suppress the zeroize-on-drop, secret retained in memory.
        core::mem::forget(self);
    }
}

impl Drop for ClsagMultisigMaskReceiver {
    fn drop(&mut self) {
        (*self.buf.lock()).zeroize();
    }
}
