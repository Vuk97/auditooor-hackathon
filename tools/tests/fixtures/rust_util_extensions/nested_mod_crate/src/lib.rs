// Fixture for inline mod tree-walking
mod outer {
    mod inner {
        pub fn nested_fn(x: u8) -> u8 {
            x.wrapping_add(1)
        }
    }
}

// Trait method without body (function_signature_item)
trait MyTrait {
    fn abstract_method(&self, msg: &str);
    fn with_result(&mut self, data: &[u8]) -> Result<(), String>;
}
