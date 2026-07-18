// E1 CLEAN fixture: same round-trip pair, but read enforces a canonical form
// (behavior-changing guard: re-serializes and rejects non_canonical encodings).
// The detector must SUPPRESS this (no malleability seam).

pub struct Widget {
    v: u64,
    orig: Vec<u8>,
}

impl Widget {
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        VarInt::write(&self.v, w)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut res = Vec::new();
        self.write(&mut res).expect("write failed");
        res
    }

    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let orig = { let mut b = Vec::new(); r.read_to_end(&mut b)?; b };
        let v = VarInt::read(&mut &orig[..])?;
        let w = Widget { v, orig: orig.clone() };
        // canonical round-trip guard: reject non_canonical encodings
        if w.serialize() != orig {
            return Err(io::Error::other("non-canonical"));
        }
        Ok(w)
    }
}
