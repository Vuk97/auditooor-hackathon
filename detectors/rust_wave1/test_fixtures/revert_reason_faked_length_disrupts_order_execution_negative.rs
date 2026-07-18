use std::fmt;

/// Safe revert reason decoder that validates length before decoding
pub struct SafeRevertDecoder;

impl SafeRevertDecoder {
    /// Maximum allowed revert reason length to prevent over-read attacks
    const MAX_REASON_LENGTH: usize = 1024;

    /// Safely decode revert reason by validating bounds first
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
        let declared_len = Self::read_u256_be(&data[32..64]) as usize;

        // CRITICAL FIX: Validate declared length against actual available bytes
        let string_start = 64;
        let available_bytes = data.len().saturating_sub(string_start);
        
        if declared_len > available_bytes {
            return Err(DecodeError::LengthMismatch {
                declared: declared_len,
                available: available_bytes,
            });
        }

        if declared_len > Self::MAX_REASON_LENGTH {
            return Err(DecodeError::ExceedsMaxLength);
        }

        // Now safely extract exactly declared_len bytes
        let string_data = &data[string_start..string_start + declared_len];
        
        // Validate UTF-8
        String::from_utf8(string_data.to_vec())
            .map_err(|_| DecodeError::InvalidUtf8)
    }

    fn read_u256_be(bytes: &[u8]) -> u64 {
        // Read the last 8 bytes (u64) from the 32-byte big-endian value
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[24..32]);
        u64::from_be_bytes(buf)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    TooShort,
    InvalidOffset,
    LengthMismatch { declared: usize, available: usize },
    ExceedsMaxLength,
    InvalidUtf8,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "data too short"),
            DecodeError::InvalidOffset => write!(f, "invalid string offset"),
            DecodeError::LengthMismatch { declared, available } => {
                write!(f, "declared length {} exceeds available {}", declared, available)
            }
            DecodeError::ExceedsMaxLength => write!(f, "reason exceeds max length"),
            DecodeError::InvalidUtf8 => write!(f, "invalid UTF-8"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_decode_valid() {
        // Encode: offset=32, len=5, "hello" padded
        let mut data = vec![0u8; 96];
        data[31] = 32; // offset
        data[63] = 5;  // length
        data[64..69].copy_from_slice(b"hello");
        
        assert_eq!(SafeRevertDecoder::decode_revert_reason(&data).unwrap(), "hello");
    }

    #[test]
    fn test_safe_decode_faked_length_blocked() {
        // Attacker provides: offset=32, len=1000, but only 5 bytes of actual data
        let mut data = vec![0u8; 69]; // only 69 bytes total
        data[31] = 32; // offset
        data[63] = 100; // declared length >> available (only 5 bytes after header)
        data[64..69].copy_from_slice(b"hello");
        
        // Should be caught by length validation, not panic or over-read
        assert!(matches!(
            SafeRevertDecoder::decode_revert_reason(&data),
            Err(DecodeError::LengthMismatch { .. })
        ));
    }
}