type Address = [u8; 20];

pub struct FallbackSetter {
    fallbackHandler: Address,
}

impl FallbackSetter {
    pub fn setFallbackHandler(&mut self, handler: Address) {
        self.fallbackHandler = handler;
    }
}
