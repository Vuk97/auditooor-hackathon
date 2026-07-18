use std::marker::PhantomData;

// Simplified LayerZero-like messaging pattern
// Clean version: _blockingLzReceive is protected by try-catch boundary

pub trait LzApp {
    fn lz_receive(&mut self, src_chain_id: u16, src_address: &[u8], nonce: u64, payload: &[u8]);
}

pub struct NonblockingLzApp<T> {
    _marker: PhantomData<T>,
    stored_payloads: Vec<(u16, Vec<u8>, u64, Vec<u8>)>,
}

impl<T> NonblockingLzApp<T> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
            stored_payloads: Vec::new(),
        }
    }

    // The try-catch boundary: ALL validation happens INSIDE the try block
    pub fn _blocking_lz_receive(
        &mut self,
        src_chain_id: u16,
        src_address: Vec<u8>,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        // SAFETY: All potentially reverting operations wrapped in try-catch
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Validation happens HERE, inside the catch boundary
            if payload.len() < 4 {
                return Err("Payload too short".to_string());
            }
            if src_address.len() != 20 {
                return Err("Invalid address length".to_string());
            }
            // Process payload
            Ok(())
        }));

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                // Expected failure: store for retry
                self.stored_payloads.push((src_chain_id, src_address, nonce, payload));
                Ok(())
            }
            Err(_) => {
                // Panic caught: store for retry
                self.stored_payloads.push((src_chain_id, src_address, nonce, payload));
                Ok(())
            }
        }
    }
}

// Concrete implementation: ONFT that uses the safe pattern
pub struct HoneyJarONFT {
    lz_app: NonblockingLzApp<HoneyJarONFT>,
    token_count: u64,
}

impl HoneyJarONFT {
    pub fn new() -> Self {
        Self {
            lz_app: NonblockingLzApp::new(),
            token_count: 0,
        }
    }

    // Delegates to safe _blocking_lz_receive
    pub fn lz_receive(&mut self, src_chain_id: u16, src_address: &[u8], nonce: u64, payload: &[u8]) {
        let _ = self.lz_app._blocking_lz_receive(
            src_chain_id,
            src_address.to_vec(),
            nonce,
            payload.to_vec(),
        );
    }
}

fn main() {
    let mut nft = HoneyJarONFT::new();
    nft.lz_receive(1, &[0u8; 20], 1, &[1, 2, 3, 4]);
    println!("Clean: channel safe");
}