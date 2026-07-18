// E1 FP-guard fixture: derive-only symmetric codec. No hand-written read/write
// bodies -> no decode seam a fuzzer could make non-canonical. Must NOT fire.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoCodec {
    a: u32,
    b: u32,
}
