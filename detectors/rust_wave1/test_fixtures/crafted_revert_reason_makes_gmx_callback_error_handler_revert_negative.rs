use std::convert::TryFrom;

/// Safe error decoding with bounded size checks and proper alignment
#[derive(Debug, Clone)]
pub struct CallbackResult {
    pub success: bool,
    pub return_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ErrorSelector([u8; 4]);

impl ErrorSelector {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes[..4]);
        Some(ErrorSelector(arr))
    }
}

#[derive(Debug, Clone)]
pub struct DecodedError {
    pub selector: ErrorSelector,
    pub message: String,
}

/// Maximum allowed revert reason size to prevent DoS
const MAX_REVERT_REASON_SIZE: usize = 4096;
/// ABI word size for alignment
const WORD_SIZE: usize = 32;

pub fn decode_revert_reason(data: &[u8]) -> Result<DecodedError, &'static str> {
    if data.len() < 4 {
        return Err("data too short for selector");
    }
    
    let selector = ErrorSelector::from_bytes(data)
        .ok_or("invalid selector")?;
    
    // Check total size bound before any further processing
    if data.len() > MAX_REVERT_REASON_SIZE {
        return Err("revert reason exceeds maximum allowed size");
    }
    
    // Ensure we have at least selector + offset + length prefix for string type
    if data.len() < 4 + WORD_SIZE * 2 {
        return Ok(DecodedError {
            selector,
            message: String::new(),
        });
    }
    
    // Read string offset (must be 0x20 for standard encoding)
    let offset_start = 4;
    let mut offset_bytes = [0u8; 8]; // only need u64, but read from word
    offset_bytes.copy_from_slice(&data[offset_start + 24..offset_start + 32]);
    let offset = u64::from_be_bytes(offset_bytes) as usize;
    
    // Validate offset is within bounds and aligned
    if offset != WORD_SIZE {
        // Non-standard offset, return raw data as message
        return Ok(DecodedError {
            selector,
            message: hex::encode(&data[4..]),
        });
    }
    
    // Read string length
    let len_start = 4 + WORD_SIZE;
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&data[len_start + 24..len_start + 32]);
    let str_len = u64::from_be_bytes(len_bytes) as usize;
    
    // Validate: length must not overflow, string must fit within data
    let str_start = 4 + WORD_SIZE + WORD_SIZE;
    if str_start.saturating_add(str_len) > data.len() {
        return Err("string length exceeds available data");
    }
    
    // Extract string data (may include padding, but we take exact length)
    let string_bytes = &data[str_start..str_start + str_len];
    
    // Validate string is valid UTF-8, fallback to hex if not
    let message = String::from_utf8(string_bytes.to_vec())
        .unwrap_or_else(|_| hex::encode(string_bytes));
    
    Ok(DecodedError { selector, message })
}

/// Safe callback execution with proper error handling
pub fn execute_callback<F>(callback: F) -> CallbackResult
where
    F: FnOnce() -> Result<Vec<u8>, Vec<u8>>,
{
    match callback() {
        Ok(data) => CallbackResult {
            success: true,
            return_data: data,
        },
        Err(err_data) => {
            // Bounded decoding prevents malicious revert reasons from causing panics
            let decoded = decode_revert_reason(&err_data)
                .unwrap_or_else(|e| DecodedError {
                    selector: ErrorSelector([0x08, 0xc3, 0x79, 0xa0]), // Error(string)
                    message: format!("decode failed: {}", e),
                });
            
            CallbackResult {
                success: false,
                return_data: decoded.message.into_bytes(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_normal_error() {
        // Standard Error(string) selector + offset 0x20 + length 5 + "hello" padded
        let mut data = vec![0x08, 0xc3, 0x79, 0xa0]; // Error(string)
        data.extend_from_slice(&[0u8; 31]); // offset high bytes
        data.push(0x20); // offset = 32
        data.extend_from_slice(&[0u8; 31]); // length high bytes
        data.push(0x05); // length = 5
        data.extend_from_slice(b"hello");
        data.extend_from_slice(&[0u8; 27]); // padding
        
        let result = decode_revert_reason(&data).unwrap();
        assert_eq!(result.message, "hello");
    }
    
    #[test]
    fn test_oversized_revert_reason_rejected() {
        let huge = vec![0u8; MAX_REVERT_REASON_SIZE + 1];
        assert!(decode_revert_reason(&huge).is_err());
    }
}