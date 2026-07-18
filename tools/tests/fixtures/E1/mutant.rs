// E1 MUTANT fixture: hand-written decode+encode round-trip pair whose read
// does NOT enforce a canonical form -> serialization-malleability candidate.
// Mirrors monero-oxide Transaction::read (no canonical round-trip guard).

pub struct Widget {
    v: u64,
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
        let v = VarInt::read(r)?;
        Ok(Widget { v })
    }
}
