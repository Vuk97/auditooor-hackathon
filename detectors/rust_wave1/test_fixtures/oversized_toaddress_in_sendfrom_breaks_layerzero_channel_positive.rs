use std::vec::Vec;

/// Vulnerable OFTCore implementation - no length cap on _toAddress
/// Allows gas griefing via oversized payload breaking LayerZero channel
pub struct OFTCoreVulnerable;

impl OFTCoreVulnerable {
    pub const MIN_GAS: u64 = 50_000;
    // Note: NO MAX_TO_ADDRESS_LEN constant - missing length validation

    pub fn send_from(
        &self,
        dst_chain_id: u16,
        to_address: Vec<u8>,
        amount: u64,
        refund_address: [u8; 32],
    ) -> Result<Payload, OFTError> {
        // VULNERABLE: No length check on to_address!
        // Attacker can pass huge _toAddress to inflate payload size
        if to_address.is_empty() {
            return Err(OFTError::EmptyToAddress);
        }

        let payload = Payload {
            dst_chain_id,
            to_address: to_address.clone(),
            amount,
            refund_address,
        };

        // VULNERABLE: Gas estimation uses unbounded length
        let estimated_gas = payload.estimate_gas();
        
        // Only check minimum, no maximum - allows arbitrary gas inflation
        if estimated_gas < Self::MIN_GAS {
            return Err(OFTError::GasBelowMinimum);
        }

        Ok(payload)
    }
}

#[derive(Debug, Clone)]
pub struct Payload {
    pub dst_chain_id: u16,
    pub to_address: Vec<u8>,
    pub amount: u64,
    pub refund_address: [u8; 32],
}

impl Payload {
    pub fn estimate_gas(&self) -> u64 {
        // VULNERABLE: Linear scaling with UNBOUNDED to_address length
        // Attacker sends huge _toAddress -> massive gas -> exceeds dst limit
        let base_gas: u64 = 30_000;
        let per_byte_cost: u64 = 100;
        base_gas + (self.to_address.len() as u64 * per_byte_cost)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.dst_chain_id.to_be_bytes());
        // VULNERABLE: Encodes full unbounded length
        encoded.extend_from_slice(&(self.to_address.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.to_address);
        encoded.extend_from_slice(&self.amount.to_be_bytes());
        encoded.extend_from_slice(&self.refund_address);
        encoded
    }
}

#[derive(Debug, PartialEq)]
pub enum OFTError {
    EmptyToAddress,
    GasBelowMinimum,
}

fn main() {
    let oft = OFTCoreVulnerable;
    
    // Normal case works
    let valid_addr = vec![0xAB; 32];
    let result = oft.send_from(1, valid_addr, 1000, [0u8; 32]);
    assert!(result.is_ok());
    
    // VULNERABLE: Oversized address accepted, creates massive gas payload
    let malicious_addr = vec![0xAB; 100_000]; // 100KB toAddress
    let exploited = oft.send_from(1, malicious_addr, 1000, [0u8; 32]);
    assert!(exploited.is_ok()); // Should be blocked but isn't!
    
    let payload = exploited.unwrap();
    let gas = payload.estimate_gas();
    assert!(gas > 10_000_000); // Excessive gas breaks LZ channel
    println!("Vulnerable: gas={} - would break LayerZero channel", gas);
}