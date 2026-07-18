use std::fmt;

/// VULNERABLE: Revert reason decoder that trusts length prefix without validation
/// This allows attackers to cause panics, garbage reads, or out-of-bounds access
pub struct VulnerableRevertDecoder;

impl VulnerableRevertDecoder {
    /// UNSAFE: Decodes revert reason without validating declared length against buffer size
    /// VULNERABILITY: Uses abi.decode pattern that trusts the length prefix
    pub fn decode_revert_reason(data: &[u8]) -> Result<String, DecodeError> {
        if data.len() < 64 {
            return Err(DecodeError::TooShort);
        }

        // Read the offset to the string data (should be 0x20 for simple encoding)
        let offset = Self::read_u256_be(&data[0..32]) as usize;
        if offset != 32 {
            return Err(DecodeError::InvalidOffset);
        }

        // Read the declared length of the string
        // VULNERABLE: No validation that declared_len <= actual remaining bytes
        let declared_len = Self::read_u256_be(&data[32..64]) as usize;

        // BUG: Directly use declared_len to slice without bounds checking!
        // This mirrors Solidity's abi.decode(data, (string)) behavior
        let string_start = 64;
        
        // VULNERABLE: Will panic on out-of-bounds or read garbage if we used get_unchecked
        // Using standard slicing here to show the logical bug - in no_std/unsafe code
        // this would be a direct over-read vulnerability
        let string_data = &data[string_start..string_start + declared_len]; // PANIC if declared_len > available
        
        // Or worse: in unsafe code this could read past allocation
        // let string_data = unsafe { 
        //     std::slice::from_raw_parts(data.as_ptr().add(string_start), declared_len)
        // };

        String::from_utf8(string_data.to_vec())
            .map_err(|_| DecodeError::InvalidUtf8)
    }

    fn read_u256_be(bytes: &[u8]) -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[24..32]);
        u64::from_be_bytes(buf)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    TooShort,
    InvalidOffset,
    InvalidUtf8,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "data too short"),
            DecodeError::InvalidOffset => write!(f, "invalid string offset"),
            DecodeError::InvalidUtf8 => write!(f, "invalid UTF-8"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "range end index")]
    fn test_vulnerable_decode_faked_length_panics() {
        // Attacker provides: offset=32, len=1000, but only 5 bytes of actual data
        let mut data = vec![0u8; 69]; // only 69 bytes total
        data[31] = 32; // offset
        data[63] = 100; // declared length >> available (only 5 bytes after header)
        data[64..69].copy_from_slice(b"hello");
        
        // VULNERABLE: This will panic due to out-of-bounds slice
        // In production, this disrupts order execution by causing callback revert
        let _result = VulnerableRevertDecoder::decode_revert_reason(&data);
    }

    #[test]
    fn test_vulnerable_decode_valid_works() {
        let mut data = vec![0u8; 96];
        data[31] = 32;
        data[63] = 5;
        data[64..69].copy_from_slice(b"hello");
        
        assert_eq!(VulnerableRevertDecoder::decode_revert_reason(&data).unwrap(), "hello");
    }
}