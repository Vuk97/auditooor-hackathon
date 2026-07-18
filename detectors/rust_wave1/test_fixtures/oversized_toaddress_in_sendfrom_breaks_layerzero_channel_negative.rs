use std::vec::Vec;

/// Safe OFTCore implementation with length-capped _toAddress
pub struct OFTCoreSafe;

impl OFTCoreSafe {
    pub const MAX_TO_ADDRESS_LEN: usize = 32;
    pub const MIN_GAS: u64 = 50_000;
    pub const MAX_GAS: u64 = 200_000;

    pub fn send_from(
        &self,
        dst_chain_id: u16,
        to_address: Vec<u8>,
        amount: u64,
        refund_address: [u8; 32],
    ) -> Result<Payload, OFTError> {
        // Enforce length cap to prevent oversized payload gas griefing
        if to_address.len() > Self::MAX_TO_ADDRESS_LEN {
            return Err(OFTError::ToAddressTooLong);
        }
        if to_address.is_empty() {
            return Err(OFTError::EmptyToAddress);
        }

        let payload = Payload {
            dst_chain_id,
            to_address: to_address.clone(),
            amount,
            refund_address,
        };

        let estimated_gas = payload.estimate_gas();
        if estimated_gas > Self::MAX_GAS {
            return Err(OFTError::GasExceedsLimit);
        }
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
        // Base gas + per-byte cost for to_address (capped by constructor)
        let base_gas: u64 = 30_000;
        let per_byte_cost: u64 = 100;
        base_gas + (self.to_address.len() as u64 * per_byte_cost)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.dst_chain_id.to_be_bytes());
        encoded.extend_from_slice(&(self.to_address.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.to_address);
        encoded.extend_from_slice(&self.amount.to_be_bytes());
        encoded.extend_from_slice(&self.refund_address);
        encoded
    }
}

#[derive(Debug, PartialEq)]
pub enum OFTError {
    ToAddressTooLong,
    EmptyToAddress,
    GasExceedsLimit,
    GasBelowMinimum,
}

fn main() {
    let oft = OFTCoreSafe;
    let valid_addr = vec![0xAB; 32];
    let result = oft.send_from(1, valid_addr, 1000, [0u8; 32]);
    assert!(result.is_ok());
    
    // Verify oversized address is rejected
    let oversized = vec![0xAB; 100];
    let blocked = oft.send_from(1, oversized, 1000, [0u8; 32]);
    assert_eq!(blocked, Err(OFTError::ToAddressTooLong));
    println!("Safe OFTCore: length cap prevents gas griefing");
}