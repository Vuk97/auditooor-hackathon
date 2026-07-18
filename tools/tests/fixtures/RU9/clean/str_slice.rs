// RU9 clean fixture - a &str byte-range slice GUARDED by is_char_boundary.
// The author has modelled UTF-8 boundaries, so a non-boundary slice cannot
// panic. RU9 must stay silent. Mirrors the shape of near
// src/utils/fmt/src/lib.rs::from_str (s[1..s.len()-1]) with the boundary guard
// added (the behavior-changing mutation target).
pub fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2 && s.is_char_boundary(1) && s.is_char_boundary(s.len() - 1) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}
