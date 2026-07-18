// clean.rs - should NOT fire the detector
//
// Safe variants: domain-specific bound check exists before the allocation call.

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
    let _ = reader.read(&mut vec);
    Ok(vec)
}

const MAX_COINBASE_SCRIPT_LEN: usize = 100;
const MIN_COINBASE_SCRIPT_LEN: usize = 2;
const SOLUTION_SIZE: usize = 1344;

/// Safe variant 1 (mirrors Input::zcash_deserialize coinbase case):
/// domain-specific upper and lower bound checks before allocation.
struct CoinbaseScript(Vec<u8>);

impl ZcashDeserialize for CoinbaseScript {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let len: CompactSizeMessage = (&mut reader).zcash_deserialize_into()?;
        let len: usize = len.into();
        if len < MIN_COINBASE_SCRIPT_LEN {
            return Err(SerializationError);
        } else if len > MAX_COINBASE_SCRIPT_LEN {
            return Err(SerializationError);
        }
        let data = zcash_deserialize_bytes_external_count(len, &mut reader)?;
        Ok(CoinbaseScript(data))
    }
}

/// Safe variant 2 (mirrors Solution::zcash_deserialize):
/// upper bound check against SOLUTION_SIZE before allocation.
struct Solution(Vec<u8>);

impl ZcashDeserialize for Solution {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let len: CompactSizeMessage = (&mut reader).zcash_deserialize_into()?;
        let len: usize = len.into();
        if len > SOLUTION_SIZE {
            return Err(SerializationError);
        }
        let data = zcash_deserialize_bytes_external_count(len, &mut reader)?;
        Ok(Solution(data))
    }
}

/// Safe variant 3: not in a ZcashDeserialize impl - should not fire.
fn unrelated_fn<R: io::Read>(mut reader: R) -> Result<Vec<u8>, SerializationError> {
    let len: CompactSizeMessage = (&mut reader).zcash_deserialize_into()?;
    zcash_deserialize_bytes_external_count(len.into(), reader)
}
