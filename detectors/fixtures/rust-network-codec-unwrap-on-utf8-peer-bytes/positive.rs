// positive.rs - SHOULD fire: String::from_utf8(...).unwrap() in a Decoder impl
// mirroring the real zebra codec.rs shape.

use std::io::Cursor;
use bytes::BytesMut;

struct Codec {
    state: DecodeState,
}

enum DecodeState {
    Head,
}

struct Message;

struct Error;

impl tokio_util::codec::Decoder for Codec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let command: [u8; 12] = [0u8; 12];
        // Simulate what zebra does: escape bytes then from_utf8(...).unwrap()
        // The escape_default chain produces ASCII bytes so technically safe,
        // but the structural pattern (from_utf8 + unwrap on bytes from peer wire)
        // is the flagged shape.
        let _cmd_str = String::from_utf8(
            command.iter()
                .cloned()
                .flat_map(std::ascii::escape_default)
                .collect()
        ).unwrap();
        Ok(None)
    }
}
