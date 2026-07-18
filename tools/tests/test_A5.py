#!/usr/bin/env python3
"""A5 encode/decode layout-trust seam - regression + non-vacuity tests.

Pins the A5 mode of tools/cross-module-trust-seam.py
(emit_encode_decode_seams): a serialize/deserialize JOIN pairing an
``encode_*`` producer that enforces a fixed *LEN* byte layout with a
``decode_*`` consumer that OMITS the exact-length/is_empty guard the layout
implies. Rows carry verdict='needs-fuzz' (advisory, NO-AUTO-CREDIT).

Matrix (pure-Rust fixtures, no external toolchain):
  - unguarded wrapper decoder   -> 1 seam (needs-fuzz).
  - guarded wrapper decoder     -> 0 seams (re-checks layout).
  - symmetric DERIVED codec     -> 0 seams (FP guard: no *LEN* producer).

Off-by-default: no env / no force -> status 'off-by-default', 0 rows.

Non-vacuity (test_mutate_len_guard_predicate): neutralise the tool's
exact-length guard regex; the GUARDED case must then collapse 0 -> 1, proving
the guard predicate is load-bearing.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "A5"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "cross_module_trust_seam_a5", TOOLS / "cross-module-trust-seam.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(tool, fixture: str, force=True):
    with tempfile.TemporaryDirectory() as td:
        ws = pathlib.Path(td)
        acct = tool.emit_encode_decode_seams(
            ws, scan_root=FX / fixture, max_rows=1000, force=force
        )
        jl = ws / ".auditooor" / "encode_decode_seams.jsonl"
        rows = [ln for ln in (jl.read_text().splitlines() if jl.exists() else []) if ln.strip()]
        return acct, rows


class A5MatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_unguarded_wrapper_one_seam(self):
        acct, rows = _run(self.tool, "codec_unguarded.rs")
        self.assertEqual(acct["status"], "ok", acct)
        self.assertEqual(len(rows), 1, f"expected 1 seam, got {rows}")
        self.assertEqual(acct["rows"], 1)
        import json
        r = json.loads(rows[0])
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertEqual(r["decoder_consumer"]["fn"], "decode_from_tx")
        self.assertFalse(r["covered_by_a2"])

    def test_guarded_wrapper_zero(self):
        acct, rows = _run(self.tool, "codec_guarded.rs")
        self.assertEqual(acct["status"], "ok", acct)
        self.assertEqual(len(rows), 0, f"guarded decoder must not fire: {rows}")

    def test_symmetric_derived_zero_fp_guard(self):
        acct, rows = _run(self.tool, "codec_derived.rs")
        self.assertEqual(acct["status"], "ok", acct)
        self.assertEqual(acct["producer_types"], 0, "derive has no handwritten producer")
        self.assertEqual(len(rows), 0, f"symmetric derive pair must not fire: {rows}")

    def test_off_by_default(self):
        os.environ.pop("AUDITOOOR_ENCODE_DECODE_SEAM", None)
        acct, rows = _run(self.tool, "codec_unguarded.rs", force=False)
        self.assertEqual(acct["status"], "off-by-default")
        self.assertEqual(len(rows), 0)

    def test_env_enables(self):
        try:
            os.environ["AUDITOOOR_ENCODE_DECODE_SEAM"] = "1"
            acct, rows = _run(self.tool, "codec_unguarded.rs", force=False)
            self.assertEqual(acct["status"], "ok")
            self.assertEqual(len(rows), 1)
        finally:
            os.environ.pop("AUDITOOOR_ENCODE_DECODE_SEAM", None)

    def test_mutate_len_guard_predicate(self):
        """Neutralise the exact-length guard regex: the GUARDED case must
        collapse 0 -> 1 (guard no longer detected), proving it is load-bearing.
        """
        tool = _load_tool()
        # Baseline: guarded fixture yields 0.
        _, base_rows = _run(tool, "codec_guarded.rs")
        self.assertEqual(len(base_rows), 0)
        # Mutate the predicate: make the .len()-compare guard undetectable.
        tool._A5_LEN_GUARD_RE = re.compile(r"\b__never_match_a5__\b")
        _, mut_rows = _run(tool, "codec_guarded.rs")
        self.assertEqual(
            len(mut_rows), 1,
            f"neutralising the len-guard predicate must expose the guarded "
            f"decoder as a seam (0 -> 1), got {mut_rows}",
        )

    def test_strict_requires_and_accepts_exact_typed_disposition(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            first = self.tool.emit_encode_decode_seams(
                ws, FX / "codec_unguarded.rs", 1000, force=True, strict=True
            )
            rows_path = ws / ".auditooor" / "encode_decode_seams.jsonl"
            row = json.loads(rows_path.read_text().splitlines()[0])
            self.assertEqual(first["strict_verdict"], "fail-cross-module-trust-seam")
            self.assertEqual(len(first["strict_unresolved_rows"]), 1)

            disp = ws / ".auditooor" / "cross_module_trust_seams_dispositions.jsonl"
            disp.write_text(json.dumps({
                "stable_id": row["stable_id"],
                "disposition_type": "covered",
                "reason": "manual codec review closes this exact seam obligation",
                "evidence_ref": "tests/A5/codec-review.txt",
            }) + "\n")
            closed = self.tool.emit_encode_decode_seams(
                ws, FX / "codec_unguarded.rs", 1000, force=True, strict=True
            )
            self.assertEqual(closed["strict_verdict"], "pass-cross-module-trust-seam")
            self.assertEqual(closed["strict_unresolved_rows"], [])
            self.assertEqual(closed["strict_resolved_rows"], 1)

    def test_strict_clean_fixture_has_evidence_backed_accounting(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            acct = self.tool.emit_encode_decode_seams(
                ws, FX / "codec_guarded.rs", 1000, force=True, strict=True
            )
            self.assertEqual(acct["strict_verdict"], "pass-cross-module-trust-seam")
            self.assertTrue(acct["substrate_evidence"])
            self.assertEqual(acct["strict_unresolved_rows"], [])

    def test_strict_missing_scan_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            acct = self.tool.emit_encode_decode_seams(
                ws, ws / "missing.rs", 1000, strict=True
            )
            self.assertEqual(acct["strict_verdict"], "fail-cross-module-trust-seam")
            self.assertIn("missing-evidence-backed-accounting", acct["strict_blockers"])

    def test_without_strict_off_by_default_remains_advisory(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            acct = self.tool.emit_encode_decode_seams(
                ws, FX / "codec_unguarded.rs", 1000, force=False, strict=False
            )
            self.assertEqual(acct["status"], "off-by-default")
            self.assertNotIn("strict_blockers", acct)

    def test_cli_strict_returns_nonzero_for_open_seam(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            rc = self.tool.main([
                "--ws", str(ws), "--mode", "encode-decode",
                "--scan-root", str(FX / "codec_unguarded.rs"), "--strict",
            ])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
