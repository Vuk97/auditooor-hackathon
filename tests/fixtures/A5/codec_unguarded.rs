// A5 fixture: layout-enforcing encoder + UNGUARDED wrapper decoder -> 1 seam.
pub struct Info {
    pub a: u64,
}

impl Info {
    pub const INFO_TX_LEN: usize = 4 + 32 * 5;

    // Layout-enforcing producer: fixed byte layout via a *LEN* const.
    pub fn encode_calldata(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::INFO_TX_LEN);
        buf.extend_from_slice(&self.a.to_be_bytes());
        buf
    }

    // DIRECT decoder that re-checks the exact length -> BENIGN (no seam).
    pub fn decode_calldata(r: &[u8]) -> Option<Self> {
        if r.len() != Self::INFO_TX_LEN {
            return None;
        }
        Some(Info { a: 0 })
    }
}

// WRAPPER decoder: trusts the callee's layout, omits the exact-length guard
// -> SEAM fires (verdict=needs-fuzz).
fn decode_from_tx(raw: &[u8]) -> Option<Info> {
    let stripped = raw.strip_prefix(&[0x7E])?;
    Info::decode_calldata(stripped)
}
