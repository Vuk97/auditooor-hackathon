use std::cell::UnsafeCell;
use std::ptr::NonNull;

#[derive(Debug)]
pub struct Global {
    ty: u32,
    vm_global_definition: Box<UnsafeCell<u64>>,
    lock: (),
}

/// # Safety
/// This is safe to send between threads because there is no thread-specific logic.
unsafe impl Send for Global {}
unsafe impl Sync for Global {}
