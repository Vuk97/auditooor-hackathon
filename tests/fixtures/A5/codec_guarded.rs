// A5 fixture: same layout-enforcing encoder, but the wrapper decoder DOES
// re-check the length -> BENIGN, 0 seams.
pub struct Info {
    pub a: u64,
}

impl Info {
    pub const INFO_TX_LEN: usize = 4 + 32 * 5;

    pub fn encode_calldata(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::INFO_TX_LEN);
        buf.extend_from_slice(&self.a.to_be_bytes());
        buf
    }

    pub fn decode_calldata(r: &[u8]) -> Option<Self> {
        if r.len() != Self::INFO_TX_LEN {
            return None;
        }
        Some(Info { a: 0 })
    }
}

// WRAPPER decoder WITH an exact-length guard -> BENIGN (no seam).
fn decode_from_tx(raw: &[u8]) -> Option<Info> {
    if raw.len() < 5 {
        return None;
    }
    let stripped = raw.strip_prefix(&[0x7E])?;
    Info::decode_calldata(stripped)
}
