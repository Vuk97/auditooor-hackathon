// RU9 mutant fixture - the is_char_boundary guard DROPPED (behavior-changing
// mutation). Only a byte `.len()` check remains, so a multibyte char at index 1
// or s.len()-1 aborts. RU9 must fire (1 hit). Mirrors near
// src/utils/fmt/src/lib.rs:62 (s[1..s.len()-1] on a &str with only a len guard).
pub fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2 {
        &s[1..s.len() - 1]
    } else {
        s
    }
}
