// RU11 CLEAN control - monero-oxide ClsagMultisigMaskReceiver-derived.
// A secret-zeroize post-condition is delegated to the Drop impl. Safety-Drop
// present, NO mem::forget / ManuallyDrop anywhere, no panic op and no early
// move inside the drop body -> the RAII runs-once/in-order invariant is intact.
// RU11 must stay SILENT (benign control).
use zeroize::Zeroize;

struct ClsagMultisigMaskReceiver {
    buf: Arc<Mutex<Option<Scalar>>>,
}

impl ClsagMultisigMaskReceiver {
    fn recv(self) -> Option<Scalar> {
        let mut lock = self.buf.lock();
        // legitimate consumption: .take()/.expect() OUTSIDE the drop body must
        // not trip the drop-scoped arms.
        let res = lock.take();
        (*lock).zeroize();
        res
    }
}

impl Drop for ClsagMultisigMaskReceiver {
    fn drop(&mut self) {
        (*self.buf.lock()).zeroize();
    }
}
