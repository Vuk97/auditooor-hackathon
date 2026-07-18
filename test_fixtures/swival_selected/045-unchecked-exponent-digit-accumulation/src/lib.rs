//! Hermetic Swival replay skeleton.
//! Boundary: arithmetic parser model only; it does not import compiler-builtins/libm.

pub mod vulnerable {
    pub fn accumulate_release_model(digits: &[u8]) -> u32 {
        let mut pexp = 0u32;
        for &b in digits {
            pexp = pexp.saturating_mul(10);
            pexp = pexp.wrapping_add((b - b'0') as u32);
        }
        pexp
    }

    pub fn accumulate_checked_model(digits: &[u8]) -> Option<u32> {
        let mut pexp = 0u32;
        for &b in digits {
            pexp = pexp.saturating_mul(10);
            pexp = pexp.checked_add((b - b'0') as u32)?;
        }
        Some(pexp)
    }
}

pub mod clean {
    pub fn accumulate(digits: &[u8]) -> u32 {
        let mut pexp = 0u32;
        for &b in digits {
            pexp = pexp.saturating_mul(10);
            pexp = pexp.saturating_add((b - b'0') as u32);
        }
        pexp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_wraps_or_fails_after_saturating_mul() {
        let digits = b"4294967296";
        assert_eq!(vulnerable::accumulate_checked_model(digits), None);
        assert!(vulnerable::accumulate_release_model(digits) < 4_294_967_290);
    }

    #[test]
    fn clean_model_saturates_after_overflow_boundary() {
        assert_eq!(clean::accumulate(b"4294967296"), u32::MAX);
    }
}
