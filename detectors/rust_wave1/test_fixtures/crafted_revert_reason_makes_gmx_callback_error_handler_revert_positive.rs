use std::convert::TryFrom;

/// VULNERABLE: Unsafe error decoding without bounds checking
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

/// VULNERABLE: No maximum size limit on revert reason
/// No WORD_SIZE constant for alignment validation

pub fn decode_revert_reason(data: &[u8]) -> Result<DecodedError, &'static str> {
    if data.len() < 4 {
        return Err("data too short for selector");
    }
    
    let selector = ErrorSelector::from_bytes(data)
        .ok_or("invalid selector")?;
    
    // VULNERABLE: No size bound check - attacker can pass massive data
    // VULNERABLE: No validation of data length before accessing offset/length
    
    // Directly read offset without checking if data is long enough
    let offset_start = 4;
    let mut offset_bytes = [0u8; 32]; // BUG: reads full 32 bytes but data may be shorter
    let available_for_offset = data.len().saturating_sub(offset_start);
    let to_copy = available_for_offset.min(32);
    offset_bytes[32 - to_copy..].copy_from_slice(&data[offset_start..offset_start + to_copy]);
    
    // VULNERABLE: Uses full 32-byte big-endian read which may include garbage
    // This panics if data is too short for the slicing above in some paths
    let offset = if data.len() >= offset_start + 32 {
        let mut temp = [0u8; 8];
        temp.copy_from_slice(&data[offset_start + 24..offset_start + 32]);
        u64::from_be_bytes(temp) as usize
    } else {
        // Fallback that may still be wrong: assumes partial data is valid
        let mut temp = [0u8; 8];
        let start = data.len().saturating_sub(8);
        temp.copy_from_slice(&data[start..]);
        u64::from_be_bytes(temp) as usize
    };
    
    // VULNERABLE: No validation that offset points within data
    // VULNERABLE: No validation that offset is properly aligned
    
    // Read length from potentially invalid location
    let len_start = 4 + offset;
    let mut len_bytes = [0u8; 32];
    
    // CRITICAL BUG: This will panic if len_start + 32 > data.len() and we try to slice
    // But even if we check, we don't validate the length value itself
    if len_start + 32 > data.len() {
        // Partial read that may produce huge incorrect length
        let available = data.len().saturating_sub(len_start);
        len_bytes[32 - available..].copy_from_slice(&data[len_start..len_start + available]);
    } else {
        len_bytes.copy_from_slice(&data[len_start..len_start + 32]);
    }
    
    let mut len_temp = [0u8; 8];
    len_temp.copy_from_slice(&len_bytes[24..32]);
    let str_len = u64::from_be_bytes(len_temp) as usize;
    
    // VULNERABLE: No check that str_len is reasonable
    // VULNERABLE: No check that str_start + str_len doesn't overflow
    let str_start = 4 + offset + 32;
    
    // This subtraction can underflow if str_start > data.len()
    // Or cause out-of-bounds if str_len is maliciously crafted
    let end = str_start + str_len;
    if end > data.len() || end < str_start { // second check is overflow check, but wrong!
        return Err("invalid string bounds");
    }
    
    let string_bytes = &data[str_start..end];
    
    // VULNERABLE: from_utf8_lossy hides encoding attacks, but the real issue is above
    let message = String::from_utf8_lossy(string_bytes).into_owned();
    
    Ok(DecodedError { selector, message })
}

/// VULNERABLE: Callback execution that propagates decode panics
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
            // VULNERABLE: unwrap() panics if decode_revert_reason fails!
            // Attacker crafts revert reason to make decode_revert_reason panic,
            // which bricks the entire transaction flow (no try/catch at this level)
            let decoded = decode_revert_reason(&err_data).unwrap();
            
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
        let mut data = vec![0x08, 0xc3, 0x79, 0xa0];
        data.extend_from_slice(&[0u8; 31]);
        data.push(0x20);
        data.extend_from_slice(&[0u8; 31]);
        data.push(0x05);
        data.extend_from_slice(b"hello");
        data.extend_from_slice(&[0u8; 27]);
        
        let result = decode_revert_reason(&data).unwrap();
        assert_eq!(result.message, "hello");
    }
    
    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value")]
    fn test_malicious_revert_reason_panics() {
        // Crafted: valid selector but offset points way out of bounds
        // This causes arithmetic issues or out-of-bounds in decode
        let mut data = vec![0x08, 0xc3, 0x79, 0xa0]; // Error(string)
        // Set offset to huge value to cause overflow/oom
        data.extend_from_slice(&[0xffu8; 32]); // offset = u64::MAX
        
        // This will fail in decode_revert_reason, then unwrap panics
        let _result = execute_callback(|| Err(data));
    }
}