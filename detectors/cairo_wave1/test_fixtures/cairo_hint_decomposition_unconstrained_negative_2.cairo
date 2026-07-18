// Negative fixture: not a Cairo file — no felt type, no hints, no starknet.
// Should produce zero findings.
fn ordinary_function(x: u64) -> u64 {
    let high = x >> 32;
    let low = x & 0xFFFF_FFFF;
    high * (1u64 << 32) + low
}
