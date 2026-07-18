#!/usr/bin/env python3
"""Regression: hunt-coverage-gate exempts FILE-ONLY queue over-inclusion soundly.

The exploit_queue carries coarse file-level tokens (a bare `adapters.rs` with no
`::fn`) that are not per-function hunt obligations. near-intents 2026-06-26: 56+
no-function data/const/type modules (method_names.rs = 73 pub const, block_events.rs
= 24 event structs) lingered as a permanent false-red.

Two exemptions, both source-confirmed and conservative:
  - _unit_is_no_function_file: a file-only unit resolving UNAMBIGUOUSLY to a single
    file with zero function decls. An ambiguous bare basename (many `lib.rs`) is NEVER
    exempted - resolving to an arbitrary match could check the wrong file.
  - _file_only_unit_hunted_at_fn: a file-only unit whose file was already hunted at
    function granularity (a `<file>::<fn>` scanned token shares its identity).
"""
import importlib.util
import unittest
from pathlib import Path
import tempfile

_TOOL = Path(__file__).resolve().parent.parent / "hunt-coverage-gate.py"
_spec = importlib.util.spec_from_file_location("hcg_fo", _TOOL)
hcg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hcg)


class NoFunctionFileExemptTest(unittest.TestCase):
    def _ws(self, tmp):
        ws = Path(tmp) / "ws"
        (ws / "src").mkdir(parents=True)
        return ws

    def test_unique_no_function_file_is_exempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "src" / "method_names.rs").write_text(
                'pub const SIGN: &str = "sign";\npub const VERIFY: &str = "verify";\n',
                encoding="utf-8")
            self.assertTrue(hcg._unit_is_no_function_file(ws, "method_names.rs"))

    def test_unique_file_with_function_not_exempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "src" / "logic.rs").write_text(
                "pub fn transfer(amount: u128) { do_it(amount); }\n", encoding="utf-8")
            self.assertFalse(hcg._unit_is_no_function_file(ws, "logic.rs"))

    def test_ambiguous_basename_never_exempt(self):
        # two lib.rs - one data-only, one with a fn. An ambiguous basename must NOT be
        # exempted even though one match has no functions (could check the wrong file).
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "src" / "a").mkdir()
            (ws / "src" / "b").mkdir()
            (ws / "src" / "a" / "lib.rs").write_text("pub const X: u8 = 1;\n", encoding="utf-8")
            (ws / "src" / "b" / "lib.rs").write_text("pub fn danger() {}\n", encoding="utf-8")
            self.assertFalse(hcg._unit_is_no_function_file(ws, "lib.rs"))

    def test_test_dir_match_excluded_so_unique_remains_exempt(self):
        # a data module unique once test trees are excluded stays exempt
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "src" / "tests").mkdir()
            (ws / "src" / "consts.rs").write_text("pub const N: u8 = 3;\n", encoding="utf-8")
            (ws / "src" / "tests" / "consts.rs").write_text("pub fn helper() {}\n", encoding="utf-8")
            # tests/ copy is excluded -> unique non-test match has no fn -> exempt
            self.assertTrue(hcg._unit_is_no_function_file(ws, "consts.rs"))

    def test_e2e_test_crate_match_excluded(self):
        # a no-fn production module that shares its basename with a fn-bearing file in
        # an e2e-tests crate must still be exempt: the test crate is excluded from
        # source resolution, so resolution is unique (near-intents conversions.rs).
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "src" / "crates").mkdir()
            (ws / "src" / "crates" / "prod").mkdir()
            (ws / "src" / "crates" / "e2e-tests").mkdir()
            (ws / "src" / "crates" / "e2e-tests" / "src").mkdir()
            (ws / "src" / "crates" / "prod" / "conversions.rs").write_text(
                "pub enum E { A }\nmod sub;\n", encoding="utf-8")
            (ws / "src" / "crates" / "e2e-tests" / "src" / "conversions.rs").write_text(
                "pub fn t() {}\npub fn u() {}\n", encoding="utf-8")
            self.assertTrue(hcg._unit_is_no_function_file(ws, "conversions.rs"))

    def test_fn_level_unit_never_treated_as_file_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "src" / "x.rs").write_text("pub const Y: u8 = 1;\n", encoding="utf-8")
            self.assertFalse(hcg._unit_is_no_function_file(ws, "x.rs::foo"))

    def test_solidity_no_function_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "src" / "Types.sol").write_text(
                "struct Transfer { uint256 amount; }\nenum Kind { A, B }\n", encoding="utf-8")
            self.assertTrue(hcg._unit_is_no_function_file(ws, "Types.sol"))


class HuntedAtFnExemptTest(unittest.TestCase):
    def test_basename_hunted_at_fn_is_exempt(self):
        scanned = {"bitcoin.rs::serialize", "other.rs::foo"}
        self.assertTrue(hcg._file_only_unit_hunted_at_fn("bitcoin.rs", scanned))

    def test_unhunted_basename_not_exempt(self):
        scanned = {"other.rs::foo"}
        self.assertFalse(hcg._file_only_unit_hunted_at_fn("bitcoin.rs", scanned))

    def test_fn_unit_not_handled_here(self):
        scanned = {"bitcoin.rs::serialize"}
        self.assertFalse(hcg._file_only_unit_hunted_at_fn("bitcoin.rs::serialize", scanned))

    def test_relpath_unit_matches_basename_token(self):
        scanned = {"src/foreign/bitcoin.rs::serialize"}
        self.assertTrue(
            hcg._file_only_unit_hunted_at_fn("src/foreign/bitcoin.rs", scanned))


if __name__ == "__main__":
    unittest.main()
