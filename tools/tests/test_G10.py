#!/usr/bin/env python3
"""G10 Go slice-aliasing / missing-defensive-copy screen - tests.

Pins tools/go-slice-aliasing-screen.py, a GENERAL trust-enforcement screen:
"the backing array of an internal slice field T.field is exclusively owned;
the read/write boundary must break aliasing with a defensive copy." Rows are
ADVISORY (verdict='needs-fuzz', auto_credit=False); it never fail-closes.

Matrix (pure-Go fixtures, no toolchain):
  aliasing_read.go  -> 1 row  (bare `return s.values`, slice field)
  guarded_read.go   -> 0 rows (slices.Clone copy; len(); non-slice field)
  aliasing_write.go -> 1 row  (bare `b.data = p`, slice param)
  guarded_write.go  -> 0 rows (make+copy; non-slice field)

Off-by-default: no env / no force -> status 'off-by-default', 0 rows.

Non-vacuity (test_neutralise_core_predicate): make `is_slice_type` always
False; EVERY planted positive must then STOP firing (1 -> 0), proving the
slice-typedness predicate is load-bearing.

Guard-detection non-vacuity (test_neutralise_write_guard): neutralise
`param_defensively_recopied`; the GUARDED write must then be exposed (0 -> 1),
proving the defensive-copy predicate is load-bearing.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "G10"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "go_slice_aliasing_screen", TOOLS / "go-slice-aliasing-screen.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(tool, fixture: str, force=True):
    with tempfile.TemporaryDirectory() as td:
        ws = pathlib.Path(td)
        acct = tool.emit_slice_aliasing(
            ws, scan_root=FX / fixture, max_rows=1000, force=force
        )
        jl = ws / ".auditooor" / "go_slice_aliasing.jsonl"
        rows = [
            json.loads(ln)
            for ln in (jl.read_text().splitlines() if jl.exists() else [])
            if ln.strip()
        ]
        return acct, rows


class G10MatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_aliasing_read_fires(self):
        acct, rows = _run(self.tool, "aliasing_read.go")
        self.assertEqual(acct["status"], "ok", acct)
        self.assertEqual(len(rows), 1, f"expected 1 read-alias, got {rows}")
        r = rows[0]
        self.assertEqual(r["kind"], "aliasing-on-read")
        self.assertEqual(r["receiver_type"], "snapshot")
        self.assertEqual(r["field"], "values")
        self.assertEqual(r["fn"], "Values")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])

    def test_guarded_read_silent(self):
        acct, rows = _run(self.tool, "guarded_read.go")
        self.assertEqual(acct["status"], "ok", acct)
        self.assertEqual(len(rows), 0, f"guarded/derived reads must be silent: {rows}")

    def test_aliasing_write_fires(self):
        acct, rows = _run(self.tool, "aliasing_write.go")
        self.assertEqual(acct["status"], "ok", acct)
        self.assertEqual(len(rows), 1, f"expected 1 write-alias, got {rows}")
        r = rows[0]
        self.assertEqual(r["kind"], "aliasing-on-write")
        self.assertEqual(r["receiver_type"], "buffer")
        self.assertEqual(r["field"], "data")
        self.assertEqual(r["fn"], "SetData")

    def test_guarded_write_silent(self):
        acct, rows = _run(self.tool, "guarded_write.go")
        self.assertEqual(acct["status"], "ok", acct)
        self.assertEqual(len(rows), 0, f"copy-before-store must be silent: {rows}")

    def test_off_by_default(self):
        os.environ.pop("go_slice_aliasing".upper(), None)
        os.environ.pop(self.tool.ENV, None)
        acct, rows = _run(self.tool, "aliasing_read.go", force=False)
        self.assertEqual(acct["status"], "off-by-default")
        self.assertEqual(len(rows), 0)

    def test_env_enables(self):
        try:
            os.environ[self.tool.ENV] = "1"
            acct, rows = _run(self.tool, "aliasing_read.go", force=False)
            self.assertEqual(acct["status"], "ok")
            self.assertEqual(len(rows), 1)
        finally:
            os.environ.pop(self.tool.ENV, None)

    def test_neutralise_core_predicate(self):
        """Neutralise is_slice_type (always False): both planted positives must
        stop firing (1 -> 0), proving slice-typedness is load-bearing."""
        tool = _load_tool()
        tool.is_slice_type = lambda t: False
        _, read_rows = _run(tool, "aliasing_read.go")
        _, write_rows = _run(tool, "aliasing_write.go")
        self.assertEqual(len(read_rows), 0,
                         f"neutralised predicate must stop the read positive: {read_rows}")
        self.assertEqual(len(write_rows), 0,
                         f"neutralised predicate must stop the write positive: {write_rows}")

    def test_neutralise_write_guard(self):
        """Neutralise param_defensively_recopied (always False): the GUARDED
        write must then be exposed (0 -> 1), proving the copy-before-store
        predicate is load-bearing."""
        tool = _load_tool()
        _, base = _run(tool, "guarded_write.go")
        self.assertEqual(len(base), 0)
        tool.param_defensively_recopied = lambda body, param: False
        _, mut = _run(tool, "guarded_write.go")
        self.assertEqual(len(mut), 1,
                         f"neutralised write-guard must expose the guarded write: {mut}")


if __name__ == "__main__":
    unittest.main()
