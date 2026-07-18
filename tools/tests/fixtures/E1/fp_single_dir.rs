// E1 FP-guard fixture: decode-only type (no encode counterpart). There is no
// round-trip oracle, so the detector must NOT emit a malleability hypothesis.

pub struct Reader {
    v: u64,
}

impl Reader {
    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let v = VarInt::read(r)?;
        Ok(Reader { v })
    }
}
