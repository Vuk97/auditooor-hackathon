// positive.rs - SHOULD fire the detector
//
// Models the Vec<u8>::ZcashDeserialize pattern in zebra-chain/src/serialization/zcash_deserialize.rs
// A CompactSize length is read from the wire, converted to usize, and passed
// directly to zcash_deserialize_bytes_external_count without a domain-specific
// bound check. A peer can supply a length near MAX_PROTOCOL_MESSAGE_LEN (~2 MiB)
// forcing a transient multi-MiB allocation before the library cap fires.

use std::io;

struct SerializationError;
struct CompactSizeMessage(u32);
impl CompactSizeMessage {
    fn into(self) -> usize { self.0 as usize }
}

trait ZcashDeserializeInto {
    fn zcash_deserialize_into<T>(&mut self) -> Result<T, SerializationError>
    where T: ZcashDeserialize;
}

trait ZcashDeserialize: Sized {
    fn zcash_deserialize<R: io::Read>(reader: R) -> Result<Self, SerializationError>;
}

fn zcash_deserialize_bytes_external_count<R: io::Read>(
    external_count: usize,
    mut reader: R,
) -> Result<Vec<u8>, SerializationError> {
    let mut vec = vec![0u8; external_count];
    // (real impl checks MAX_U8_ALLOCATION here but not domain-specific)
    let _ = reader.read(&mut vec);
    Ok(vec)
}

/// Vulnerable: reads CompactSize len, converts to usize, then immediately
/// calls zcash_deserialize_bytes_external_count without any domain bound check.
impl ZcashDeserialize for Vec<u8> {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let len: CompactSizeMessage = (&mut reader).zcash_deserialize_into()?;
        zcash_deserialize_bytes_external_count(len.into(), reader)
    }
}

/// Second vulnerable instance: two-statement form, no precheck.
struct ArbitraryPayload(Vec<u8>);

impl ZcashDeserialize for ArbitraryPayload {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let len: CompactSizeMessage = (&mut reader).zcash_deserialize_into()?;
        let len: usize = len.into();
        let data = zcash_deserialize_bytes_external_count(len, &mut reader)?;
        Ok(ArbitraryPayload(data))
    }
}
