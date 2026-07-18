//! Hermetic Swival fixture skeleton.
//! Boundary: layout-size smoke only; it does not run SOLID networking APIs.

pub mod vulnerable {
    #[repr(C)]
    pub struct SockaddrStorage {
        s2_len: u8,
        ss_family: u8,
        s2_data1: [i8; 2],
        s2_data2: [u32; 3],
    }

    pub fn storage_size() -> usize {
        std::mem::size_of::<SockaddrStorage>()
    }
}

pub mod clean {
    #[repr(C)]
    pub struct SockaddrStorage {
        s2_len: u8,
        ss_family: u8,
        s2_data1: [i8; 2],
        s2_data2: [u32; 6],
    }

    pub fn storage_size() -> usize {
        std::mem::size_of::<SockaddrStorage>()
    }
}

#[repr(C)]
pub struct SockaddrIn6 {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

pub fn ipv6_size() -> usize {
    std::mem::size_of::<SockaddrIn6>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_storage_is_smaller_than_ipv6() {
        assert!(vulnerable::storage_size() < ipv6_size());
    }

    #[test]
    fn clean_model_storage_can_hold_ipv6() {
        assert!(clean::storage_size() >= ipv6_size());
    }
}
