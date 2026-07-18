use std::cell::UnsafeCell;
use std::ptr::NonNull;
use parking_lot::Mutex;

#[derive(Debug)]
pub struct Global {
    ty: u32,
    vm_global_definition: Box<UnsafeCell<u64>>,
    lock: Mutex<()>,
}

/// # Safety
/// This is safe to send between threads because there is no thread-specific logic.
unsafe impl Send for Global {}
/// # Safety
/// This is safe to share between threads because it uses a `Mutex` internally.
unsafe impl Sync for Global {}
