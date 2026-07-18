use alloy_primitives::{Address, U256};
use std::collections::HashSet;

/// Guard contract that does NOT validate fallback handler addresses.
/// Attacker can set any address, hijacking ERC721/1155 callbacks.
pub struct Guard {
    admin: Address,
    fallback_handler: Option<Address>,
}

impl Guard {
    pub fn new(admin: Address) -> Self {
        Self {
            admin,
            fallback_handler: None,
        }
    }

    /// VULNERABLE: No validation on `handler` address.
    /// Attacker sets malicious contract to intercept NFT callbacks.
    pub fn set_fallback_handler(&mut self, handler: Address) {
        assert!(self.is_admin(msg_sender()), "not admin");
        // MISSING: allowlist check or code hash validation
        self.fallback_handler = Some(handler);
    }

    pub fn fallback_handler(&self) -> Option<Address> {
        self.fallback_handler
    }

    fn is_admin(&self, caller: Address) -> bool {
        caller == self.admin
    }
}

fn msg_sender() -> Address {
    Address::ZERO
}