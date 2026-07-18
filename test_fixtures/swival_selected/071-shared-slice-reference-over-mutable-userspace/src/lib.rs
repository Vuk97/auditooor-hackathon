//! Hermetic Swival fixture skeleton.
//! Boundary: models reference construction shape only; no UB or exploit proof is claimed.

pub mod vulnerable {
    pub unsafe fn iter_model(ptr: *const u8, len: usize) -> std::slice::Iter<'static, u8> {
        std::slice::from_raw_parts(ptr, len).iter()
    }
}

pub mod clean {
    use std::marker::PhantomData;

    pub struct UserRef<T: ?Sized> {
        ptr: *const T,
    }

    pub struct Iter<'a> {
        ptr: *const u8,
        len: usize,
        _marker: PhantomData<&'a UserRef<u8>>,
    }

    impl<'a> Iter<'a> {
        pub fn new(ptr: *const u8, len: usize) -> Self {
            Self { ptr, len, _marker: PhantomData }
        }
    }

    impl<'a> Iterator for Iter<'a> {
        type Item = *const UserRef<u8>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.len == 0 {
                return None;
            }
            let ptr = self.ptr;
            self.ptr = self.ptr.wrapping_add(1);
            self.len -= 1;
            Some(ptr as *const UserRef<u8>)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_builds_slice_iterator_over_raw_user_memory() {
        let data = Box::leak(vec![1u8, 2, 3].into_boxed_slice());
        let collected: Vec<u8> = unsafe { vulnerable::iter_model(data.as_ptr(), data.len()) }.copied().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    #[test]
    fn clean_model_iterates_raw_addresses_without_materializing_u8_refs() {
        let data = [1u8, 2, 3];
        let got: Vec<usize> = clean::Iter::new(data.as_ptr(), data.len()).map(|p| p as usize).collect();
        assert_eq!(got.len(), 3);
        assert_eq!(got[1] - got[0], 1);
    }
}
