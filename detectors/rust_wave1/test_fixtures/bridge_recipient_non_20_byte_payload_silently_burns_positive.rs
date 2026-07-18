use std::convert::TryInto;

/// Vulnerable: validates with <= check instead of exact equality,
/// allowing shorter payloads to pass validation.
/// Bug: non-20-byte recipients silently burn funds.
pub fn validate_to_length(recipient: &[u8]) -> Result<(), &'static str> {
    // VULNERABLE: allows 16-byte or any length <= 20 to pass
    if recipient.len() > 20 {
        return Err("recipient exceeds max length");
    }
    // Missing: check for exact 20 bytes
    Ok(())
}

/// Decodes address by reading first 20 bytes regardless of actual payload length.
/// When payload is shorter (e.g., 16 bytes), this reads garbage/zero-padded data
/// or causes undefined behavior - funds go to wrong address and are burned.
pub fn decode_address_vulnerable(payload: &[u8]) -> [u8; 20] {
    validate_to_length(payload).unwrap(); // Vulnerable validation passes short payloads
    
    let mut addr = [0u8; 20];
    // BUG: copies min(payload.len(), 20) bytes - for 16-byte payload, last 4 bytes are zeros
    // This creates an unintended recipient address where funds are lost
    let copy_len = payload.len().min(20);
    addr[..copy_len].copy_from_slice(&payload[..copy_len]);
    addr
}

/// Bridge transfer with vulnerable validation.
pub fn bridge_transfer_vulnerable(amount: u64, recipient_payload: &[u8]) {
    let recipient = decode_address_vulnerable(recipient_payload);
    // Funds sent to corrupted/zero-padded address - permanently lost
    println!("Transfer {} to {:?} - MAY BE BURNED", amount, recipient);
}

fn main() {
    // This 16-byte payload passes validation but creates wrong address
    let malicious_recipient = [0xABu8; 16];
    
    // VULNERABLE: passes validation, but creates 0xABAB...AB0000...0000 address
    // Funds are burned/sent to uncontrolled address
    bridge_transfer_vulnerable(1000, &malicious_recipient);
    
    // Even empty payload passes!
    bridge_transfer_vulnerable(500, &[]);
    
    println!("Bug demonstrated: non-20-byte payloads silently burn funds");
}