use std::marker::PhantomData;

// Simplified LayerZero-like messaging pattern
// VULNERABLE version: _blockingLzReceive has REVERT BEFORE try-catch boundary

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

    // Base implementation with try-catch
    pub fn _blocking_lz_receive(
        &mut self,
        src_chain_id: u16,
        src_address: Vec<u8>,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Process payload (minimal work here)
            Ok(())
        }));

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                self.stored_payloads.push((src_chain_id, src_address, nonce, payload));
                Ok(())
            }
            Err(_) => {
                self.stored_payloads.push((src_chain_id, src_address, nonce, payload));
                Ok(())
            }
        }
    }
}

// VULNERABLE: ONFT that OVERRIDES and adds REVERT before try-catch
pub struct HoneyJarONFT {
    lz_app: NonblockingLzApp<HoneyJarONFT>,
    token_count: u64,
    max_supply: u64,
}

impl HoneyJarONFT {
    pub fn new() -> Self {
        Self {
            lz_app: NonblockingLzApp::new(),
            token_count: 0,
            max_supply: 100,
        }
    }

    // VULNERABILITY: Revert happens BEFORE calling _blocking_lz_receive
    // This bypasses the try-catch safety net and bricks the LZ channel
    pub fn lz_receive(&mut self, src_chain_id: u16, src_address: &[u8], nonce: u64, payload: &[u8]) {
        // BUG: These checks happen OUTSIDE the try-catch boundary
        // If they fail, the entire transaction reverts, blocking the channel
        let mint_amount = self.parse_mint_amount(payload);
        
        // CRITICAL: This revert is NOT caught by NonblockingLzApp's try-catch
        if self.token_count + mint_amount > self.max_supply {
            panic!("Exceeds max supply: channel blocked!"); // or: require! macro
        }

        // Only AFTER the unchecked revert do we reach the safe path
        let _ = self.lz_app._blocking_lz_receive(
            src_chain_id,
            src_address.to_vec(),
            nonce,
            payload.to_vec(),
        );
    }

    fn parse_mint_amount(&self, payload: &[u8]) -> u64 {
        if payload.len() >= 8 {
            u64::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
                payload[4], payload[5], payload[6], payload[7],
            ])
        } else {
            0
        }
    }

    // Alternative vulnerable pattern: override _blocking_lz_receive with pre-check revert
    pub fn _blocking_lz_receive_override(
        &mut self,
        src_chain_id: u16,
        src_address: Vec<u8>,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        // BUG: Validation revert BEFORE any try-catch wrapping
        let mint_amount = self.parse_mint_amount(&payload);
        assert!(self.token_count + mint_amount <= self.max_supply, "Revert bricks channel");

        // Only then delegate to parent's safe implementation
        self.lz_app._blocking_lz_receive(src_chain_id, src_address, nonce, payload)
    }
}

fn main() {
    let mut nft = HoneyJarONFT::new();
    // This call will panic and block the channel
    nft.lz_receive(1, &[0u8; 20], 1, &[255u8; 8]); // large mint amount
    println!("This line never reached");
}