// A5 FP-guard fixture: a symmetric DERIVED codec (no handwritten
// layout-enforcing encoder). No *LEN* producer is registered, so even an
// unguarded wrapper decoder must NOT fire (derive pairs are safe).
#[derive(RlpEncodable, RlpDecodable)]
pub struct Info {
    pub a: u64,
}

// Unguarded wrapper, but the type has NO handwritten encode_* producer ->
// no seam (symmetric-derive FP guard).
fn decode_from_tx(raw: &[u8]) -> Option<Info> {
    let stripped = raw.strip_prefix(&[0x7E])?;
    Info::decode_calldata(stripped).ok()
}
