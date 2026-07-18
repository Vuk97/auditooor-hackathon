// Negative fixture 2: not a Bellperson file — plain Rust allocation.
struct Buffer {
    data: Vec<u8>,
}

fn allocate_buffer(size: usize) -> Buffer {
    Buffer {
        data: vec![0u8; size],
    }
}
