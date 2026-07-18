#!/usr/bin/env python3
"""RU9 - str byte-slice char-boundary panic advisory axis.

Non-vacuous: each positive asserts a specific hit, each negative asserts the
absence; mutating the predicate (dropping the char-boundary guard, the str-type
gate, the range-slice shape, or the ascii-delimiter suppression) breaks a case.
Pins the mutation-verified near near_fmt::from_str-derived fixture pair
(clean=0, mutant=1).
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-detector-runner.py"
FIX = Path(__file__).resolve().parent / "fixtures" / "RU9"


def _load():
    spec = importlib.util.spec_from_file_location("rust_detector_runner_ru9", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_runner_ru9"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _write(ws: Path, rel: str, body: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _ss_hits(ws: Path):
    os.environ["AUDITOOR_RUST_STRSLICE_AXIS"] = "1"
    summary = MOD.scan_workspace(ws)
    axis = summary.get("rust_strslice_axis", {})
    return axis.get("hypotheses", [])


class RU9Tests(unittest.TestCase):
    def test_len_bounded_str_slice_fires(self):
        # &str sliced by [1..s.len()-1], only a .len() guard -> fires.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/a.rs", """
                pub fn f(s: &str) -> &str {
                    if s.len() >= 2 { &s[1..s.len() - 1] } else { s }
                }
                """)
            hits = _ss_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["str_var"], "s")

    def test_string_typed_let_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/b.rs", """
                pub fn g(raw: &[u8]) -> String {
                    let text = String::from_utf8_lossy(raw).to_string();
                    let head = &text[..text.len() - 3];
                    head.to_owned()
                }
                """)
            hits = _ss_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["str_var"], "text")

    def test_char_boundary_guard_suppresses(self):
        # is_char_boundary in the body -> author modelled boundaries, silent.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/c.rs", """
                pub fn f(s: &str) -> &str {
                    if s.is_char_boundary(1) { &s[1..s.len() - 1] } else { s }
                }
                """)
            self.assertEqual(len(_ss_hits(ws)), 0)

    def test_char_indices_guard_suppresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/d.rs", """
                pub fn f(s: &str) -> &str {
                    let n = s.char_indices().count();
                    &s[1..n]
                }
                """)
            self.assertEqual(len(_ss_hits(ws)), 0)

    def test_ascii_prefix_literal_slice_suppressed(self):
        # Literal-only bounds after a starts_with ASCII-prefix guard -> benign.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/e.rs", """
                pub fn f(s: &str) -> &str {
                    if s.starts_with("0x") { &s[2..6] } else { s }
                }
                """)
            self.assertEqual(len(_ss_hits(ws)), 0)

    def test_byte_typed_var_not_str_silent(self):
        # &[u8] byte var sliced -> RU1/RU2 territory, RU9 (str-typed) silent.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/f.rs", """
                pub fn f(bytes: &[u8]) -> &[u8] {
                    &bytes[1..bytes.len() - 1]
                }
                """)
            self.assertEqual(len(_ss_hits(ws)), 0)

    def test_whole_range_slice_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/g.rs", """
                pub fn f(s: &str) -> &str {
                    &s[..]
                }
                """)
            self.assertEqual(len(_ss_hits(ws)), 0)

    def test_vec_string_container_not_str_silent(self):
        # Vec<String> is not str-sliceable in the char-boundary sense.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/h.rs", """
                pub fn f(names: Vec<String>) -> usize {
                    let _first = &names[1..names.len() - 1];
                    names.len()
                }
                """)
            self.assertEqual(len(_ss_hits(ws)), 0)

    def test_axis_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/a.rs", """
                pub fn f(s: &str) -> &str {
                    if s.len() >= 2 { &s[1..s.len() - 1] } else { s }
                }
                """)
            os.environ.pop("AUDITOOR_RUST_STRSLICE_AXIS", None)
            summary = MOD.scan_workspace(ws)
            self.assertNotIn("rust_strslice_axis", summary)

    def test_needs_fuzz_no_auto_credit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/a.rs", """
                pub fn f(s: &str) -> &str {
                    if s.len() >= 2 { &s[1..s.len() - 1] } else { s }
                }
                """)
            os.environ["AUDITOOR_RUST_STRSLICE_AXIS"] = "1"
            summary = MOD.scan_workspace(ws)
            axis = summary["rust_strslice_axis"]
            self.assertEqual(axis["verdict"], "needs-fuzz")
            self.assertFalse(axis["auto_credit"])
            h = axis["hypotheses"][0]
            self.assertEqual(h["extra"]["verdict"], "needs-fuzz")
            self.assertEqual(
                h["extra"]["impact_contract"]["status"], "advisory_until_harnessed"
            )

    def test_committed_fixtures(self):
        # Mutation-kill: near from_str-derived pair (clean guarded=0, mutant=1).
        clean = _ss_hits(FIX / "clean")
        mut = _ss_hits(FIX / "mutant")
        self.assertEqual(len(clean), 0)
        self.assertEqual(len(mut), 1)
        self.assertEqual(mut[0]["extra"]["function"], "strip_quotes")


if __name__ == "__main__":
    unittest.main()
