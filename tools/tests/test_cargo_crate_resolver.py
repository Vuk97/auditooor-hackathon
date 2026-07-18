#!/usr/bin/env python3
"""Tests for tools/cargo-crate-resolver.py (Wave O-A).

8 unit tests covering:
  1. Single-crate workspace (one Cargo.toml at root with [package])
  2. Multi-crate workspace ([workspace] at root, sub-crates with own [package])
  3. Path with no Cargo.toml ancestor → None
  4. Cargo.toml without [package] table → None
  5. Crate name with dashes (base-succinct-client-utils)
  6. Crate name with underscores (my_crate_lib)
  7. File nested several levels deep → finds parent Cargo.toml
  8. find_workspace_root_and_crate: returns workspace root + crate name
  9. find_workspace_root_and_crate: no package → None
 10. Cargo.toml has both [workspace] and [package] (root crate) → name returned
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "cargo-crate-resolver.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("cargo_crate_resolver", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cargo_crate_resolver"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestResolveCrateName(unittest.TestCase):
    """Tests for resolve_crate_name()."""

    def test_single_crate_workspace(self):
        """Single-crate workspace: Cargo.toml at root has [package] name."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "Cargo.toml", '[package]\nname = "my-crate"\nversion = "0.1.0"\n')
            _write(root / "src" / "main.rs", "fn main() {}")
            name = _MOD.resolve_crate_name(root / "src" / "main.rs")
            self.assertEqual(name, "my-crate")

    def test_multi_crate_workspace(self):
        """Multi-crate: walk up from sub-crate src/ to sub-crate Cargo.toml."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Workspace root
            _write(root / "Cargo.toml", '[workspace]\nmembers = ["crates/foo"]\n')
            # Sub-crate
            _write(
                root / "crates" / "foo" / "Cargo.toml",
                '[package]\nname = "foo-crate"\nversion = "0.1.0"\n',
            )
            _write(root / "crates" / "foo" / "src" / "lib.rs", "pub fn foo() {}")
            name = _MOD.resolve_crate_name(root / "crates" / "foo" / "src" / "lib.rs")
            self.assertEqual(name, "foo-crate")

    def test_no_cargo_toml_returns_none(self):
        """No Cargo.toml in any ancestor → None."""
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b" / "c"
            deep.mkdir(parents=True)
            src = deep / "foo.rs"
            src.write_text("fn foo() {}")
            name = _MOD.resolve_crate_name(src)
            self.assertIsNone(name)

    def test_cargo_toml_without_package_returns_none(self):
        """Cargo.toml exists but has no [package] → None."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "Cargo.toml", '[workspace]\nmembers = []\n')
            _write(root / "src" / "lib.rs", "")
            name = _MOD.resolve_crate_name(root / "src" / "lib.rs")
            self.assertIsNone(name)

    def test_crate_name_with_dashes(self):
        """Crate name containing dashes is returned verbatim."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "Cargo.toml",
                '[package]\nname = "base-succinct-client-utils"\nversion = "0.1.0"\n',
            )
            _write(root / "src" / "precompiles" / "mod.rs", "")
            name = _MOD.resolve_crate_name(root / "src" / "precompiles" / "mod.rs")
            self.assertEqual(name, "base-succinct-client-utils")

    def test_crate_name_with_underscores(self):
        """Crate name containing underscores."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "Cargo.toml",
                '[package]\nname = "my_crate_lib"\nversion = "0.1.0"\n',
            )
            _write(root / "src" / "lib.rs", "")
            name = _MOD.resolve_crate_name(root / "src" / "lib.rs")
            self.assertEqual(name, "my_crate_lib")

    def test_deeply_nested_file(self):
        """File nested 5 levels deep still finds the parent Cargo.toml."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "Cargo.toml", '[package]\nname = "deep-crate"\nversion = "0.1.0"\n')
            deep = root / "src" / "a" / "b" / "c" / "d"
            deep.mkdir(parents=True)
            src = deep / "module.rs"
            src.write_text("fn x() {}")
            name = _MOD.resolve_crate_name(src)
            self.assertEqual(name, "deep-crate")

    def test_workspace_root_stops_walk(self):
        """workspace_root arg prevents walking above the boundary."""
        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp) / "outer"
            inner = outer / "inner"
            # Outer has a Cargo.toml that would match if walk weren't bounded
            _write(outer / "Cargo.toml", '[package]\nname = "outer-crate"\nversion = "0.1.0"\n')
            # Inner has no Cargo.toml of its own
            inner.mkdir(parents=True)
            src = inner / "foo.rs"
            src.write_text("fn foo() {}")
            # Without workspace_root, would find outer's Cargo.toml
            name_unbounded = _MOD.resolve_crate_name(src)
            self.assertEqual(name_unbounded, "outer-crate")
            # With workspace_root=inner, walk stays within inner → None
            name_bounded = _MOD.resolve_crate_name(src, workspace_root=inner)
            self.assertIsNone(name_bounded)


class TestFindWorkspaceRootAndCrate(unittest.TestCase):
    """Tests for find_workspace_root_and_crate()."""

    def test_returns_workspace_root_and_crate_name(self):
        """find_workspace_root_and_crate returns (workspace_root, crate_name)."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "Cargo.toml", '[workspace]\nmembers = ["crates/bar"]\n')
            _write(
                root / "crates" / "bar" / "Cargo.toml",
                '[package]\nname = "bar-crate"\nversion = "0.1.0"\n',
            )
            src = root / "crates" / "bar" / "src" / "lib.rs"
            src.parent.mkdir(parents=True)
            src.write_text("")
            result = _MOD.find_workspace_root_and_crate(src)
            self.assertIsNotNone(result)
            ws_root, crate_name = result
            self.assertEqual(ws_root.resolve(), root.resolve())
            self.assertEqual(crate_name, "bar-crate")

    def test_no_package_returns_none(self):
        """No [package] anywhere → None."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "Cargo.toml", '[workspace]\nmembers = []\n')
            src = root / "src" / "lib.rs"
            src.parent.mkdir(parents=True)
            src.write_text("")
            result = _MOD.find_workspace_root_and_crate(src)
            self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
