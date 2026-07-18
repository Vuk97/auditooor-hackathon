use std::collections::HashSet;

type Address = [u8; 20];

pub struct FallbackSetter {
    allowed_handlers: HashSet<Address>,
    fallback_handler: Option<Address>,
}

impl FallbackSetter {
    pub fn set_fallback_handler(&mut self, handler: Address) {
        assert!(
            self.allowed_handlers.contains(&handler),
            "handler not allowed"
        );
        self.fallback_handler = Some(handler);
    }
}
