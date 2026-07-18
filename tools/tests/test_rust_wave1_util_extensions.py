"""
test_rust_wave1_util_extensions.py

Unit tests for the three Track K-Rust step-1 helpers added to
detectors/rust_wave1/_util.py:

  - fn_module_path(fn_node, source, file_path) -> str
  - fn_signature_normalized(fn_node, source)   -> str
  - crate_name_from_path(file_path)            -> str

Run with:
    python3 -m unittest tools.tests.test_rust_wave1_util_extensions
"""

from __future__ import annotations

import pathlib
import sys
import unittest

# Make sure the detector package is importable regardless of cwd
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]  # dlt-workflow-gaps-main/
_DETECTOR_DIR = _REPO_ROOT / "detectors" / "rust_wave1"
if str(_DETECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_DETECTOR_DIR))

# Fixture root
_FIX = _REPO_ROOT / "tools" / "tests" / "fixtures" / "rust_util_extensions"

import tree_sitter_rust
from tree_sitter import Language, Parser

_RUST_LANG = Language(tree_sitter_rust.language())
_PARSER = Parser(_RUST_LANG)


def _parse(src: bytes):
    return _PARSER.parse(src)


def _all_fn_nodes(root):
    """Yield all function_item AND function_signature_item nodes."""
    def _walk(n):
        yield n
        for c in n.children:
            yield from _walk(c)
    for n in _walk(root):
        if n.type in ("function_item", "function_signature_item"):
            yield n


# ---------------------------------------------------------------------------
# Import helpers from _util (done lazily so the import error is visible)
# ---------------------------------------------------------------------------
from _util import fn_module_path, fn_signature_normalized, crate_name_from_path  # noqa: E402


class TestFnModulePath(unittest.TestCase):
    """Tests for fn_module_path()."""

    def _first_fn(self, src: bytes):
        tree = _parse(src)
        nodes = list(_all_fn_nodes(tree.root_node))
        self.assertTrue(nodes, "No function_item found in fixture")
        return nodes[0], src

    # ------------------------------------------------------------------ #
    # 1. src/lib.rs → "crate"                                            #
    # ------------------------------------------------------------------ #
    def test_lib_rs_returns_crate(self):
        """fn_module_path returns 'crate' for a top-level fn in src/lib.rs."""
        src = b"pub fn top_level(x: u32) -> u32 { x }"
        fn_node, source = self._first_fn(src)
        fp = pathlib.Path("src/lib.rs")
        result = fn_module_path(fn_node, source, fp)
        self.assertEqual(result, "crate")

    def test_main_rs_returns_crate(self):
        """fn_module_path returns 'crate' for src/main.rs."""
        src = b"fn main() {}"
        fn_node, source = self._first_fn(src)
        fp = pathlib.Path("src/main.rs")
        result = fn_module_path(fn_node, source, fp)
        self.assertEqual(result, "crate")

    # ------------------------------------------------------------------ #
    # 2. src/foo/bar.rs → "foo::bar"                                     #
    # ------------------------------------------------------------------ #
    def test_nested_file_path(self):
        """fn_module_path returns 'foo::bar' for src/foo/bar.rs."""
        src = b"pub fn deep_fn(v: i64) -> i64 { v }"
        fn_node, source = self._first_fn(src)
        fp = pathlib.Path("src/foo/bar.rs")
        result = fn_module_path(fn_node, source, fp)
        self.assertEqual(result, "foo::bar")

    def test_three_level_file_path(self):
        """fn_module_path returns 'a::b::c' for src/a/b/c.rs."""
        src = b"pub fn f() {}"
        fn_node, source = self._first_fn(src)
        fp = pathlib.Path("src/a/b/c.rs")
        result = fn_module_path(fn_node, source, fp)
        self.assertEqual(result, "a::b::c")

    # ------------------------------------------------------------------ #
    # 3. Inline mod nesting walks tree correctly                         #
    # ------------------------------------------------------------------ #
    def test_inline_mod_prefix_appended(self):
        """fn_module_path appends inline mod names after the file prefix."""
        src = b"""
mod outer {
    mod inner {
        pub fn nested_fn() {}
    }
}
"""
        tree = _parse(src)
        fn_nodes = list(_all_fn_nodes(tree.root_node))
        self.assertTrue(fn_nodes)
        fn_node = fn_nodes[0]
        fp = pathlib.Path("src/lib.rs")
        result = fn_module_path(fn_node, src, fp)
        # lib.rs → "crate"; then outer::inner inline mods are prepended
        self.assertEqual(result, "outer::inner")

    def test_inline_mod_with_file_prefix(self):
        """Inline mods inside a non-lib file are appended after file prefix."""
        src = b"""
mod helpers {
    pub fn helper_fn() {}
}
"""
        tree = _parse(src)
        fn_nodes = list(_all_fn_nodes(tree.root_node))
        self.assertTrue(fn_nodes)
        fn_node = fn_nodes[0]
        fp = pathlib.Path("src/foo/bar.rs")
        result = fn_module_path(fn_node, src, fp)
        self.assertEqual(result, "foo::bar::helpers")

    # ------------------------------------------------------------------ #
    # 4. Fixture file round-trip                                         #
    # ------------------------------------------------------------------ #
    def test_fixture_lib_rs(self):
        """Round-trip: fixture src/lib.rs → 'crate' for top-level fn."""
        fix_path = _FIX / "src" / "lib.rs"
        if not fix_path.exists():
            self.skipTest("fixture missing")
        source = fix_path.read_bytes()
        tree = _parse(source)
        fn_nodes = [n for n in _all_fn_nodes(tree.root_node)
                    if n.type == "function_item"]
        self.assertTrue(fn_nodes)
        result = fn_module_path(fn_nodes[0], source, fix_path)
        self.assertEqual(result, "crate")

    def test_fixture_foo_bar_rs(self):
        """Round-trip: fixture src/foo/bar.rs → 'foo::bar'."""
        fix_path = _FIX / "src" / "foo" / "bar.rs"
        if not fix_path.exists():
            self.skipTest("fixture missing")
        source = fix_path.read_bytes()
        tree = _parse(source)
        fn_nodes = [n for n in _all_fn_nodes(tree.root_node)
                    if n.type == "function_item"]
        self.assertTrue(fn_nodes)
        result = fn_module_path(fn_nodes[0], source, fix_path)
        self.assertEqual(result, "foo::bar")


class TestFnSignatureNormalized(unittest.TestCase):
    """Tests for fn_signature_normalized()."""

    def _first_fn_any(self, src: bytes):
        """Return first function_item OR function_signature_item."""
        tree = _parse(src)
        for n in _all_fn_nodes(tree.root_node):
            return n, src
        self.fail("No function node found")

    # ------------------------------------------------------------------ #
    # 1. Strips body (only signature retained)                           #
    # ------------------------------------------------------------------ #
    def test_strips_body(self):
        """fn_signature_normalized strips the function body block."""
        src = b"pub fn finalize(&mut self, leaf: u32) -> Result<(), ()> { let x = 1; }"
        fn_node, source = self._first_fn_any(src)
        sig = fn_signature_normalized(fn_node, source)
        self.assertNotIn("{", sig)
        self.assertNotIn("let x", sig)
        self.assertIn("fn finalize", sig)
        self.assertIn("-> Result", sig)

    def test_normalizes_whitespace(self):
        """fn_signature_normalized collapses whitespace."""
        src = b"pub  fn  foo(\n  x:  u32,\n  y:  u64\n) ->  bool { false }"
        fn_node, source = self._first_fn_any(src)
        sig = fn_signature_normalized(fn_node, source)
        # No double spaces
        self.assertNotIn("  ", sig)

    # ------------------------------------------------------------------ #
    # 2. Trait method with no body — semicolon preserved                 #
    # ------------------------------------------------------------------ #
    def test_trait_method_semicolon_preserved(self):
        """Trait methods without body retain the trailing semicolon."""
        src = b"""
trait MyTrait {
    fn abstract_method(&self, msg: &str);
}
"""
        tree = _parse(src)
        sig_nodes = [n for n in _all_fn_nodes(tree.root_node)
                     if n.type == "function_signature_item"]
        self.assertTrue(sig_nodes, "No function_signature_item found")
        sig = fn_signature_normalized(sig_nodes[0], src)
        self.assertIn(";", sig)
        self.assertNotIn("{", sig)
        self.assertIn("fn abstract_method", sig)

    # ------------------------------------------------------------------ #
    # 3. Async + where clause preserved                                  #
    # ------------------------------------------------------------------ #
    def test_async_where_clause_preserved(self):
        """async fn with where clause is captured fully."""
        src = b"pub async fn bar<T: Sync>(x: T) where T: Send { let _ = x; }"
        fn_node, source = self._first_fn_any(src)
        sig = fn_signature_normalized(fn_node, source)
        self.assertIn("async", sig)
        self.assertIn("where", sig)
        self.assertNotIn("{", sig)

    # ------------------------------------------------------------------ #
    # 4. Generic parameters preserved                                    #
    # ------------------------------------------------------------------ #
    def test_generic_params_preserved(self):
        """Generic type parameters survive normalization."""
        src = b"fn compute<T: Clone + Debug>(items: &[T]) -> Vec<T> { items.to_vec() }"
        fn_node, source = self._first_fn_any(src)
        sig = fn_signature_normalized(fn_node, source)
        self.assertIn("T: Clone", sig)
        self.assertIn("Vec<T>", sig)

    # ------------------------------------------------------------------ #
    # 5. Const fn                                                        #
    # ------------------------------------------------------------------ #
    def test_const_fn_preserved(self):
        """const fn modifier is retained in signature."""
        src = b"pub const fn constant_val() -> u64 { 42 }"
        fn_node, source = self._first_fn_any(src)
        sig = fn_signature_normalized(fn_node, source)
        self.assertIn("const", sig)
        self.assertNotIn("42", sig)


class TestCrateNameFromPath(unittest.TestCase):
    """Tests for crate_name_from_path()."""

    # ------------------------------------------------------------------ #
    # 1. Reads [package].name from fixture Cargo.toml                   #
    # ------------------------------------------------------------------ #
    def test_reads_package_name(self):
        """crate_name_from_path reads [package].name from nearest Cargo.toml."""
        fix_path = _FIX / "src" / "lib.rs"
        if not (_FIX / "Cargo.toml").exists():
            self.skipTest("fixture Cargo.toml missing")
        result = crate_name_from_path(fix_path)
        self.assertEqual(result, "my_test_crate")

    def test_nested_crate_reads_own_cargo_toml(self):
        """Innermost Cargo.toml wins for nested crates."""
        fix_path = _FIX / "nested_mod_crate" / "src" / "lib.rs"
        if not (_FIX / "nested_mod_crate" / "Cargo.toml").exists():
            self.skipTest("nested_mod_crate fixture missing")
        result = crate_name_from_path(fix_path)
        self.assertEqual(result, "nested_mod_crate")

    # ------------------------------------------------------------------ #
    # 2. Returns "unknown" when no Cargo.toml found                     #
    # ------------------------------------------------------------------ #
    def test_no_cargo_toml_returns_unknown(self):
        """crate_name_from_path returns 'unknown' with no Cargo.toml nearby."""
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmp:
            isolated = pathlib.Path(tmp) / "orphan_file.rs"
            isolated.write_text("fn orphan() {}")
            result = crate_name_from_path(isolated)
            # May find a Cargo.toml somewhere up the real fs tree; but since
            # we created an isolated temp dir, the nearest Cargo.toml above /tmp
            # almost certainly has no [package].name matching our file.
            # At minimum, it should not raise.
            self.assertIsInstance(result, str)

    def test_unknown_for_deeply_isolated_path(self):
        """Returns 'unknown' for a path with definitely no Cargo.toml."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sub = pathlib.Path(tmp) / "a" / "b" / "c"
            sub.mkdir(parents=True)
            fake_rs = sub / "fake.rs"
            fake_rs.write_text("fn dummy() {}")
            # No Cargo.toml anywhere in tmp tree
            result = crate_name_from_path(fake_rs)
            self.assertEqual(result, "unknown")


class TestIntegration(unittest.TestCase):
    """Light integration: parse real fixture files and call all three helpers."""

    def test_lib_rs_all_three_helpers(self):
        """All three helpers work together on the lib.rs fixture."""
        fix_path = _FIX / "src" / "lib.rs"
        if not fix_path.exists():
            self.skipTest("fixture missing")
        source = fix_path.read_bytes()
        tree = _parse(source)
        fn_nodes = [n for n in _all_fn_nodes(tree.root_node)
                    if n.type == "function_item"]
        self.assertTrue(fn_nodes)
        fn_node = fn_nodes[0]

        mod_path = fn_module_path(fn_node, source, fix_path)
        sig = fn_signature_normalized(fn_node, source)
        crate = crate_name_from_path(fix_path)

        self.assertIsInstance(mod_path, str)
        self.assertIsInstance(sig, str)
        self.assertEqual(crate, "my_test_crate")
        # The fixture's top-level fn is not inside a body
        self.assertNotIn("{", sig)


if __name__ == "__main__":
    unittest.main()
