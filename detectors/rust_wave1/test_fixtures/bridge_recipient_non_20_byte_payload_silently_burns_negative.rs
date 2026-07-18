use std::convert::TryInto;

/// Validates that recipient bytes are exactly 20 bytes (Ethereum address length).
/// Clean version: strict length check prevents silent burn.
pub fn validate_recipient_length(recipient: &[u8]) -> Result<[u8; 20], &'static str> {
    if recipient.len() != 20 {
        return Err("recipient must be exactly 20 bytes");
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(recipient);
    Ok(addr)
}

/// Decodes address from validated payload.
pub fn decode_address(payload: &[u8]) -> Result<[u8; 20], &'static str> {
    let addr = validate_recipient_length(payload)?;
    Ok(addr)
}

/// Bridge transfer that ensures recipient is valid before processing.
pub fn bridge_transfer(amount: u64, recipient_payload: &[u8]) -> Result<(), &'static str> {
    let recipient = decode_address(recipient_payload)?;
    // Process transfer to validated recipient...
    println!("Transfer {} to {:?}", amount, recipient);
    Ok(())
}

fn main() {
    // Valid 20-byte recipient
    let valid_recipient = [1u8; 20];
    assert!(bridge_transfer(100, &valid_recipient).is_ok());
    
    // Invalid lengths rejected
    let short_recipient = [1u8; 16];
    assert!(bridge_transfer(100, &short_recipient).is_err());
    
    let long_recipient = [1u8; 32];
    assert!(bridge_transfer(100, &long_recipient).is_err());
    
    println!("All tests passed - no silent burns");
}