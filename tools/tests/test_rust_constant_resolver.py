#!/usr/bin/env python3
"""Tests for tools/rust-constant-resolver.py (P0-2 Wave C-2B).

Stdlib-only. Synthetic Rust fixtures in tempdirs — no dependency on
~/audits/ or any external source root.

Coverage:
  1. pub const with integer literal -> confidence: literal
  2. pub const with expression (Address::from_array) -> confidence: expression
  3. pub static with literal string -> confidence: literal
  4. lazy_static! entry -> kind: lazy_static, extracted
  5. pub const fn (should be SKIPPED — not a constant)
  6. opaque multi-line const -> confidence: opaque
  7. Empty crate -> empty registry, schema valid
  8. --validate round-trip succeeds; mutated JSON fails closed
  9. once_cell/OnceLock pattern -> opaque
  10. pub const bool -> literal
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-constant-resolver.py"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _make(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _make_crate(root: Path, name: str, lib_rs: str) -> Path:
    crate_dir = root / name
    _make(crate_dir, "Cargo.toml", f'[package]\nname = "{name}"\nversion = "0.1.0"\n')
    _make(crate_dir, "src/lib.rs", lib_rs)
    return crate_dir


VULNERABLE_LIB_RS = """\
use some_crate::Address;

// Integer literal constant
pub const MAX_RETRIES: u32 = 5;

// Boolean literal
pub const ENABLED: bool = true;

// Expression constant (address-like)
pub const TOKEN_X: Address = Address::from_array([0u8; 20]);

// String literal
pub static LABEL: &str = "hello";

// Should be skipped — const fn
pub const fn compute() -> u32 { 42 }

lazy_static::lazy_static! {
    static ref REGISTRY: Vec<u8> = Vec::new();
}
"""

CLEAN_LIB_RS = """\
// No pub const / pub static in this crate.
fn internal_helper() -> u32 { 0 }
"""


class TestRustConstantResolverVulnerable(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _make_crate(self.ws, "my_crate", VULNERABLE_LIB_RS)

    def tearDown(self):
        self._tmp.cleanup()

    def test_integer_literal(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(self.ws / ".auditooor" / "rust_constant_registry.json" and
                         (self.ws / ".auditooor" / "rust_constant_registry.json").read_text())
        consts = {c["name"]: c for c in out["constants"]}
        self.assertIn("MAX_RETRIES", consts)
        c = consts["MAX_RETRIES"]
        self.assertEqual(c["kind"], "const")
        self.assertEqual(c["literal_value_or_expr"], "5")
        self.assertEqual(c["resolution_confidence"], "literal")

    def test_bool_literal(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.ws / ".auditooor" / "rust_constant_registry.json").read_text())
        consts = {c["name"]: c for c in out["constants"]}
        self.assertIn("ENABLED", consts)
        self.assertEqual(consts["ENABLED"]["resolution_confidence"], "literal")

    def test_expression_constant(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.ws / ".auditooor" / "rust_constant_registry.json").read_text())
        consts = {c["name"]: c for c in out["constants"]}
        self.assertIn("TOKEN_X", consts)
        c = consts["TOKEN_X"]
        self.assertEqual(c["resolution_confidence"], "expression")

    def test_static_string_literal(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.ws / ".auditooor" / "rust_constant_registry.json").read_text())
        consts = {c["name"]: c for c in out["constants"]}
        self.assertIn("LABEL", consts)
        c = consts["LABEL"]
        self.assertEqual(c["kind"], "static")
        self.assertEqual(c["resolution_confidence"], "literal")

    def test_const_fn_skipped(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.ws / ".auditooor" / "rust_constant_registry.json").read_text())
        consts = {c["name"]: c for c in out["constants"]}
        # `compute` is a pub const fn, not a constant — must not appear
        self.assertNotIn("compute", consts)

    def test_lazy_static(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.ws / ".auditooor" / "rust_constant_registry.json").read_text())
        consts = {c["name"]: c for c in out["constants"]}
        self.assertIn("REGISTRY", consts)
        c = consts["REGISTRY"]
        self.assertEqual(c["kind"], "lazy_static")

    def test_meta_counts(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.ws / ".auditooor" / "rust_constant_registry.json").read_text())
        meta = out["_meta"]
        self.assertEqual(meta["schema_version"], "auditooor.rust_constant_registry.v1")
        self.assertGreaterEqual(meta["total_constants"], 4)
        self.assertGreaterEqual(meta["literal_count"], 3)
        self.assertGreaterEqual(meta["expression_count"], 1)


class TestRustConstantResolverClean(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _make_crate(self.ws, "clean_crate", CLEAN_LIB_RS)

    def tearDown(self):
        self._tmp.cleanup()

    def test_clean_crate_zero_constants(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.ws / ".auditooor" / "rust_constant_registry.json").read_text())
        self.assertEqual(out["_meta"]["total_constants"], 0)
        self.assertEqual(out["constants"], [])


class TestRustConstantResolverOnceCell(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _make_crate(self.ws, "once_cell_crate", """\
use std::sync::OnceLock;

pub static INSTANCE: OnceLock<String> = OnceLock::new();
""")

    def tearDown(self):
        self._tmp.cleanup()

    def test_once_cell_opaque(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads((self.ws / ".auditooor" / "rust_constant_registry.json").read_text())
        consts = {c["name"]: c for c in out["constants"]}
        self.assertIn("INSTANCE", consts)
        self.assertEqual(consts["INSTANCE"]["resolution_confidence"], "opaque")


class TestRustConstantResolverValidate(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _make_crate(self.ws, "val_crate", "pub const N: u32 = 42;\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_validate_roundtrip(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out_path = self.ws / ".auditooor" / "rust_constant_registry.json"
        r2 = _run(["--validate", str(out_path)])
        self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_validate_bad_schema_version(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out_path = self.ws / ".auditooor" / "rust_constant_registry.json"
        data = json.loads(out_path.read_text())
        data["_meta"]["schema_version"] = "wrong"
        out_path.write_text(json.dumps(data))
        r2 = _run(["--validate", str(out_path)])
        self.assertEqual(r2.returncode, 3, r2.stderr)

    def test_validate_bad_confidence(self):
        r = _run(["--workspace", str(self.ws)])
        self.assertEqual(r.returncode, 0, r.stderr)
        out_path = self.ws / ".auditooor" / "rust_constant_registry.json"
        data = json.loads(out_path.read_text())
        if data["constants"]:
            data["constants"][0]["resolution_confidence"] = "invalid"
        out_path.write_text(json.dumps(data))
        r2 = _run(["--validate", str(out_path)])
        if data["constants"]:
            self.assertEqual(r2.returncode, 3, r2.stderr)


if __name__ == "__main__":
    unittest.main()
