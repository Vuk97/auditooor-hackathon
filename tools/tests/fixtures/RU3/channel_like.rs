// RU3 fixture mirroring base-azul native_channel.rs read/read_exact shape.
// `read` clamps len with .min(buf.len()) (guarded); `read_exact` copies the
// whole untrusted `data` into `buf` with NO in-fn length guard (unguarded).

pub fn read(buf: &mut [u8], data: Vec<u8>) -> usize {
    let len = data.len().min(buf.len());
    buf[..len].copy_from_slice(&data[..len]);
    len
}

pub fn read_exact(buf: &mut [u8], data: Vec<u8>) -> usize {
    buf[..].copy_from_slice(&data[..]);
    buf.len()
}
