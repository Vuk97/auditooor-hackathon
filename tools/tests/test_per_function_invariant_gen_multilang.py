#!/usr/bin/env python3
"""Tests for the LANGUAGE-AWARE generalization of per-function-invariant-gen.py.

Covers the additive --lang {rust,go,move,cairo} paths. The Solidity default path
is covered by the existing test_per_function_invariant_gen.py and must remain
unchanged (a regression assertion is included here too).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "_pfig_ml", str(_TOOLS / "per-function-invariant-gen.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_pfig_ml"] = mod
    spec.loader.exec_module(mod)
    return mod


GEN = _load()


def _write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class TestRustPath(unittest.TestCase):
    def test_rust_discovers_functions_and_emits_harnesses(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "vault.rs",
                   "pub fn deposit(amount: u64) -> u64 { amount * 2 }\n"
                   "pub fn withdraw(shares: u64) -> u64 { shares / 2 }\n"
                   "fn helper(x: u64) -> u64 { x }\n"
                   "#[test]\nfn test_skip() {}\n")
            rc = GEN.main(["--workspace", str(ws), "--lang", "rust", "--json"])
            self.assertEqual(rc, 0)
            manifest = json.loads(
                (ws / "poc-tests" / "per_function_invariants" / "manifest.json").read_text())
            self.assertEqual(manifest["language"], "rust")
            names = {f["function"] for f in manifest["functions"]}
            self.assertIn("deposit", names)
            self.assertIn("withdraw", names)
            self.assertIn("helper", names)
            self.assertNotIn("test_skip", names)  # test- prefixed skipped
            # harness file written, idiomatic rust, sentinel assert
            row = next(f for f in manifest["functions"] if f["function"] == "deposit")
            self.assertTrue(row["harness_path"].endswith(".rs"))
            body = Path(row["harness_path"]).read_text()
            self.assertIn("#[test]", body)
            self.assertIn("assert!(true)", body)
            # manifest carries the producer-consumed keys
            self.assertIn("source", row)
            self.assertIn("harness_contract", row)
            self.assertIsNone(row["halmos_root"])

    def test_rust_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "m.rs", "pub fn f(x: u64) -> u64 { x }\n")
            GEN.main(["--workspace", str(ws), "--lang", "rust", "--dry-run"])
            self.assertFalse((ws / "poc-tests").exists())


class TestGoPath(unittest.TestCase):
    def test_go_discovers_funcs_methods_skips_tests(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "keeper.go",
                   "package keeper\n"
                   "func (k Keeper) SetBalance(addr string, amt int64) {}\n"
                   "func Deposit(amt int64) int64 { return amt }\n"
                   "func TestSkipMe(t *testing.T) {}\n")
            # a *_test.go file must be excluded entirely
            _write(ws / "src" / "keeper_test.go",
                   "package keeper\nfunc Helper() {}\n")
            rc = GEN.main(["--workspace", str(ws), "--lang", "go", "--json"])
            self.assertEqual(rc, 0)
            manifest = json.loads(
                (ws / "poc-tests" / "per_function_invariants" / "manifest.json").read_text())
            names = {f["function"] for f in manifest["functions"]}
            self.assertIn("SetBalance", names)   # method on receiver
            self.assertIn("Deposit", names)
            self.assertNotIn("TestSkipMe", names)
            self.assertNotIn("Helper", names)    # from _test.go (excluded)
            row = next(f for f in manifest["functions"] if f["function"] == "Deposit")
            body = Path(row["harness_path"]).read_text()
            self.assertIn("import \"testing\"", body)
            self.assertIn("func Test", body)
            self.assertIn("f.Fuzz", body)         # fuzz scaffold present


class TestMoveCairoPaths(unittest.TestCase):
    def test_move_scaffold(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "bank.move",
                   "module 0x1::bank {\n public fun transfer(a: u64) {}\n entry fun mint(a: u64) {}\n}\n")
            GEN.main(["--workspace", str(ws), "--lang", "move", "--json"])
            manifest = json.loads(
                (ws / "poc-tests" / "per_function_invariants" / "manifest.json").read_text())
            names = {f["function"] for f in manifest["functions"]}
            self.assertIn("transfer", names)
            self.assertIn("mint", names)
            row = next(f for f in manifest["functions"] if f["function"] == "transfer")
            body = Path(row["harness_path"]).read_text()
            self.assertIn("#[test]", body)
            self.assertIn("fun test_", body)

    def test_cairo_scaffold(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "pool.cairo",
                   "fn swap(a: felt252) {}\npub fn add_liquidity(a: felt252) {}\n")
            GEN.main(["--workspace", str(ws), "--lang", "cairo", "--json"])
            manifest = json.loads(
                (ws / "poc-tests" / "per_function_invariants" / "manifest.json").read_text())
            names = {f["function"] for f in manifest["functions"]}
            self.assertIn("swap", names)
            self.assertIn("add_liquidity", names)


class TestSolidityRegressionUnchanged(unittest.TestCase):
    def test_default_lang_is_solidity_halmos(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "Vault.sol",
                   "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.13;\n"
                   "contract Vault { uint256 public t;\n"
                   " function deposit(uint256 a) external { t += a; }\n"
                   " function peek() external view returns (uint256) { return t; } }\n")
            # No --lang => solidity default
            GEN.main(["--workspace", str(ws), "--json"])
            manifest = json.loads(
                (ws / "poc-tests" / "per_function_invariants" / "manifest.json").read_text())
            names = {f["function"] for f in manifest["functions"]}
            self.assertIn("deposit", names)
            self.assertNotIn("peek", names)  # view excluded (unchanged behavior)
            row = next(f for f in manifest["functions"] if f["function"] == "deposit")
            self.assertTrue(row["harness_path"].endswith(".t.sol"))
            self.assertEqual(row["harness_contract"], "Halmos_Vault_deposit")


if __name__ == "__main__":
    unittest.main()
