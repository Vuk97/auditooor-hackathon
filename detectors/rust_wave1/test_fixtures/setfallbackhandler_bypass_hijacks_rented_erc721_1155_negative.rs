use alloy_primitives::{Address, U256};
use std::collections::HashSet;

/// Guard contract that validates fallback handler addresses
/// against an allowlist before setting them.
pub struct Guard {
    admin: Address,
    allowed_handlers: HashSet<Address>,
    fallback_handler: Option<Address>,
}

impl Guard {
    pub fn new(admin: Address) -> Self {
        Self {
            admin,
            allowed_handlers: HashSet::new(),
            fallback_handler: None,
        }
    }

    pub fn add_allowed_handler(&mut self, handler: Address) {
        assert!(self.is_admin(msg_sender()), "not admin");
        self.allowed_handlers.insert(handler);
    }

    /// SECURE: Validates that the handler is in the allowlist.
    pub fn set_fallback_handler(&mut self, handler: Address) {
        assert!(self.is_admin(msg_sender()), "not admin");
        assert!(
            self.allowed_handlers.contains(&handler),
            "handler not in allowlist"
        );
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