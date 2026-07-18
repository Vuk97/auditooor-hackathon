// clean.rs - should NOT fire: uses from_utf8_lossy (the safe alternative)

use bytes::BytesMut;

struct SafeCodec;
struct Message;
struct Error;

impl tokio_util::codec::Decoder for SafeCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let command: [u8; 12] = [0u8; 12];
        // Safe: from_utf8_lossy replaces invalid sequences instead of panicking
        let _cmd_str = String::from_utf8_lossy(&command).to_string();
        Ok(None)
    }
}
