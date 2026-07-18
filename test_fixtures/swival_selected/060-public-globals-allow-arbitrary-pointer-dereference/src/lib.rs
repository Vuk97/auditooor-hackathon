//! Hermetic Swival fixture skeleton.
//! Boundary: models the public-global-to-safe-wrapper predicate only; not proof of stdlib impact.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub mod vulnerable {
    use super::*;

    pub mod globals {
        use super::*;
        pub static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        pub static BOOT_SERVICES_FLAG: AtomicBool = AtomicBool::new(false);
    }

    #[repr(C)]
    pub struct FakeSystemTable {
        pub boot_services: *mut c_void,
    }

    pub fn boot_services() -> Option<*mut c_void> {
        if !globals::BOOT_SERVICES_FLAG.load(Ordering::Acquire) {
            return None;
        }
        let table = globals::SYSTEM_TABLE.load(Ordering::Acquire) as *const FakeSystemTable;
        Some(unsafe { (*table).boot_services })
    }
}

pub mod clean {
    use super::*;

    mod globals {
        use super::*;
        pub static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        pub static BOOT_SERVICES_FLAG: AtomicBool = AtomicBool::new(false);
    }

    #[repr(C)]
    pub struct FakeSystemTable {
        pub boot_services: *mut c_void,
    }

    pub unsafe fn init_for_fixture(table: *mut c_void) {
        globals::SYSTEM_TABLE.store(table, Ordering::Release);
        globals::BOOT_SERVICES_FLAG.store(true, Ordering::Release);
    }

    pub fn boot_services() -> Option<*mut c_void> {
        if !globals::BOOT_SERVICES_FLAG.load(Ordering::Acquire) {
            return None;
        }
        let table = globals::SYSTEM_TABLE.load(Ordering::Acquire) as *const FakeSystemTable;
        Some(unsafe { (*table).boot_services })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_public_global_can_feed_safe_wrapper() {
        let mut table = vulnerable::FakeSystemTable { boot_services: 0xdead_beefusize as *mut c_void };
        vulnerable::globals::BOOT_SERVICES_FLAG.store(true, Ordering::Release);
        vulnerable::globals::SYSTEM_TABLE.store(&mut table as *mut _ as *mut c_void, Ordering::Release);
        assert_eq!(vulnerable::boot_services().unwrap() as usize, 0xdead_beef);
    }

    #[test]
    fn clean_model_requires_unsafe_internal_initialization() {
        let mut table = clean::FakeSystemTable { boot_services: 0xcafe_babeusize as *mut c_void };
        unsafe { clean::init_for_fixture(&mut table as *mut _ as *mut c_void) };
        assert_eq!(clean::boot_services().unwrap() as usize, 0xcafe_babe);
    }
}
