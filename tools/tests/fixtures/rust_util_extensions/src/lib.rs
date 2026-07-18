// Fixture for fn_module_path "crate" edge-case (src/lib.rs -> crate)
pub fn top_level_fn(x: u32) -> u32 {
    x + 1
}

mod inline_mod {
    pub fn inside_inline_mod() -> bool {
        true
    }
}
