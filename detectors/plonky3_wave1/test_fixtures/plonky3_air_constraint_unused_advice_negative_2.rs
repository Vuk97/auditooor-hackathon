// Negative fixture 2: not a Plonky3 file (plain Rust, no p3_air imports).
use std::collections::HashMap;

struct MyProcessor {
    data: Vec<u32>,
}

impl MyProcessor {
    fn eval(&self, builder: &mut Vec<u32>) {
        for item in &self.data {
            builder.push(*item);
        }
    }
}
