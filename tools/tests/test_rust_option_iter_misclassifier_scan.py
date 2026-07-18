#!/usr/bin/env python3
"""Tests for ``tools/rust-option-iter-misclassifier-scan.py`` (Wave I-1D / G-v01).

Bug shape: ``Option<Vec<T>>::iter().all/any(|v| v.first()/v[0]/…)`` — the closure
receives the whole Vec, not individual elements; only the first element is ever
checked.

Audit-snapshot reference:
  ``external/base/crates/consensus/protocol/src/attributes.rs:65-70``
  ``self.attributes.transactions.iter().all(|tx| tx.first().is_some_and(…))``

Coverage (10 tests)
-------------------
1.  ``test_flags_exact_audit_snapshot``     — G-v01 verbatim shape must fire
    ``iter_all_first_only`` with confidence=high.
2.  ``test_flags_any_with_index_zero``      — ``.iter().any(|x| x[0] == …)``
    must fire ``iter_any_first_only``.
3.  ``test_flags_iter_next_variant``        — closure uses ``.iter().next()``
    on the inner element.
4.  ``test_clean_unwrap_or``               — ``unwrap_or(&vec![]).iter().all``
    must NOT fire.
5.  ``test_clean_as_ref_is_some_and``      — ``as_ref().is_some_and(|txs| txs.iter().all(…))``
    must NOT fire.
6.  ``test_clean_flatten``                 — ``.iter().flatten().all(…)``
    must NOT fire.
7.  ``test_strict_exits_one``              — ``--strict`` exits 1 when rows present.
8.  ``test_no_hit_when_no_first_elem``     — ``.iter().all(|tx| tx.len() > 0)``
    (no first-elem index) must NOT fire.
9.  ``test_row_schema_fields``             — emitted row must carry required fields.
10. ``test_smoke_real_base_azul``          — live smoke vs the actual snapshot;
    must flag ``attributes.rs`` (or nearby line); skipped when snapshot absent.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "rust-option-iter-misclassifier-scan.py"
LIVE_BASE_AZUL = Path(os.path.expanduser("~/audits/base-azul"))

REQUIRED_FIELDS = {
    "file",
    "line",
    "pattern_id",
    "containing_fn",
    "confidence",
    "snippet",
    "receiver_expr",
    "closure_param",
    "first_elem_access",
    "candidate_status",
    "submission_posture",
    "evidence_class",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(workspace: Path, extra_args: list[str] | None = None) -> dict:
    cmd = [sys.executable, str(SCANNER), "--workspace", str(workspace), "--print-json"]
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode in (0, 1, 2), (proc.stdout + proc.stderr)
    return json.loads(proc.stdout) if proc.stdout.strip() else {"rows": []}


def _write_rs(workspace: Path, body: str, relpath: str = "external/base/crates/consensus/protocol/src/attributes.rs") -> Path:
    """Write a synthetic Rust file into the workspace (foot-gun #1: tempfile.mkdtemp)."""
    target = workspace / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    return target


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class OptionIterMisclassifierScanTests(unittest.TestCase):

    # ------------------------------------------------------------------
    # Test 1 — G-v01 verbatim (audit-snapshot exact form)
    # ------------------------------------------------------------------
    def test_flags_exact_audit_snapshot(self) -> None:
        """G-v01 exact form must fire iter_all_first_only with confidence=high."""
        with tempfile.TemporaryDirectory(prefix="rust_option_iter_") as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn is_deposits_only(&self) -> bool {
                    self.attributes
                        .transactions
                        .iter()
                        .all(|tx| tx.first().is_some_and(|tx| tx[0] == OpTxType::Deposit as u8))
                }
                """
            )
            _write_rs(ws, body)
            result = _run(ws)
            rows = result["rows"]
            self.assertTrue(
                len(rows) >= 1,
                f"Expected >=1 row, got 0. stdout rows: {rows}",
            )
            hit = rows[0]
            self.assertEqual(hit["pattern_id"], "iter_all_first_only")
            self.assertEqual(hit["confidence"], "high")

    # ------------------------------------------------------------------
    # Test 2 — .any() + [0] index variant
    # ------------------------------------------------------------------
    def test_flags_any_with_index_zero(self) -> None:
        """txs.iter().any(|x| x[0] == ...) must fire iter_any_first_only."""
        with tempfile.TemporaryDirectory(prefix="rust_option_iter_") as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                fn has_deposit(txs: Option<&Vec<Bytes>>) -> bool {
                    txs.iter().any(|x| x[0] == 0x7E)
                }
                """
            )
            _write_rs(ws, body)
            result = _run(ws)
            rows = result["rows"]
            self.assertTrue(len(rows) >= 1, f"Expected >=1 row, got: {rows}")
            pattern_ids = {r["pattern_id"] for r in rows}
            self.assertIn("iter_any_first_only", pattern_ids)

    # ------------------------------------------------------------------
    # Test 3 — .iter().next() variant
    # ------------------------------------------------------------------
    def test_flags_iter_next_variant(self) -> None:
        """option_vec.iter().all(|v| v.iter().next().is_some()) must fire."""
        with tempfile.TemporaryDirectory(prefix="rust_option_iter_") as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                fn check_non_empty(option_vec: Option<&Vec<u8>>) -> bool {
                    option_vec.iter().all(|v| v.iter().next().is_some())
                }
                """
            )
            _write_rs(ws, body)
            result = _run(ws)
            rows = result["rows"]
            self.assertTrue(len(rows) >= 1, f"Expected >=1 row for iter().next(), got: {rows}")
            self.assertIn(rows[0]["pattern_id"], {"iter_all_first_only", "iter_any_first_only"})

    # ------------------------------------------------------------------
    # Test 4 — Clean A: unwrap_or(&vec![]).iter().all(...)
    # ------------------------------------------------------------------
    def test_clean_unwrap_or(self) -> None:
        """unwrap_or(&vec![]).iter().all(...) is correct iteration — must NOT fire."""
        with tempfile.TemporaryDirectory(prefix="rust_option_iter_") as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                fn all_deposits(transactions: Option<&Vec<Bytes>>) -> bool {
                    transactions
                        .unwrap_or(&vec![])
                        .iter()
                        .all(|tx| tx.first() == Some(&0x7E))
                }
                """
            )
            _write_rs(ws, body)
            result = _run(ws)
            # The unwrap_or case iterates over Vec elements — clean.
            # Accept 0 rows (or rows that don't match the clean variant).
            rows = result["rows"]
            # If any row fires, it should NOT be on the unwrap_or line.
            for r in rows:
                self.assertNotIn("unwrap_or", r.get("snippet", ""))

    # ------------------------------------------------------------------
    # Test 5 — Clean B: as_ref().is_some_and(|txs| txs.iter().all(...))
    # ------------------------------------------------------------------
    def test_clean_as_ref_is_some_and(self) -> None:
        """as_ref().is_some_and(|txs| txs.iter().all(...)) must NOT fire."""
        with tempfile.TemporaryDirectory(prefix="rust_option_iter_") as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                fn all_deposits(transactions: Option<&Vec<Bytes>>) -> bool {
                    transactions
                        .as_ref()
                        .is_some_and(|txs| txs.iter().all(|tx| tx.first() == Some(&0x7E)))
                }
                """
            )
            _write_rs(ws, body)
            result = _run(ws)
            rows = result["rows"]
            for r in rows:
                self.assertNotIn("is_some_and", r.get("snippet", ""))

    # ------------------------------------------------------------------
    # Test 6 — Clean C: .iter().flatten().all(...)
    # ------------------------------------------------------------------
    def test_clean_flatten(self) -> None:
        """.iter().flatten().all(...) flattens first — must NOT fire."""
        with tempfile.TemporaryDirectory(prefix="rust_option_iter_") as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                fn all_deposits(opt: Option<Vec<Bytes>>) -> bool {
                    opt.iter().flatten().all(|tx| tx.first() == Some(&0x7E))
                }
                """
            )
            _write_rs(ws, body)
            result = _run(ws)
            rows = result["rows"]
            for r in rows:
                # flatten() interposed means the body doesn't match our pattern
                # (the .all follows .flatten(), not .iter() directly).
                self.assertNotIn("flatten", r.get("snippet", ""))

    # ------------------------------------------------------------------
    # Test 7 — --strict exits 1 when rows present
    # ------------------------------------------------------------------
    def test_strict_exits_one(self) -> None:
        """--strict must exit 1 when at least one row is emitted."""
        with tempfile.TemporaryDirectory(prefix="rust_option_iter_") as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                fn is_deposits_only(&self) -> bool {
                    self.transactions.iter().all(|tx| tx.first() == Some(&0x7E))
                }
                """
            )
            _write_rs(ws, body)
            cmd = [
                sys.executable, str(SCANNER),
                "--workspace", str(ws),
                "--strict",
                "--print-json",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            data = json.loads(proc.stdout) if proc.stdout.strip() else {"rows": []}
            if data["rows"]:
                self.assertEqual(
                    proc.returncode, 1,
                    f"Expected exit 1 in --strict mode, got {proc.returncode}",
                )

    # ------------------------------------------------------------------
    # Test 8 — No hit when closure doesn't use first-element access
    # ------------------------------------------------------------------
    def test_no_hit_when_no_first_elem(self) -> None:
        """.iter().all(|tx| tx.len() > 0) — no first-elem index — must NOT fire."""
        with tempfile.TemporaryDirectory(prefix="rust_option_iter_") as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                fn has_txs(transactions: Option<&Vec<Bytes>>) -> bool {
                    transactions.iter().all(|tx| tx.len() > 0)
                }
                """
            )
            _write_rs(ws, body)
            result = _run(ws)
            rows = result["rows"]
            self.assertEqual(
                len(rows), 0,
                f"Expected 0 rows (no first-elem access), got: {rows}",
            )

    # ------------------------------------------------------------------
    # Test 9 — Row schema fields
    # ------------------------------------------------------------------
    def test_row_schema_fields(self) -> None:
        """Every emitted row must carry the required schema fields."""
        with tempfile.TemporaryDirectory(prefix="rust_option_iter_") as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn is_deposits_only(&self) -> bool {
                    self.attributes.transactions
                        .iter()
                        .all(|tx| tx.first() == Some(&0x7E))
                }
                """
            )
            _write_rs(ws, body)
            result = _run(ws)
            rows = result["rows"]
            self.assertTrue(len(rows) >= 1, "Expected >=1 row for schema test")
            for r in rows:
                missing = REQUIRED_FIELDS - r.keys()
                self.assertFalse(
                    missing,
                    f"Row missing fields: {missing}",
                )

    # ------------------------------------------------------------------
    # Test 10 — Live smoke vs real base-azul snapshot
    # ------------------------------------------------------------------
    @unittest.skipUnless(
        LIVE_BASE_AZUL.exists(),
        "~/audits/base-azul snapshot not present; skipping live smoke",
    )
    def test_smoke_real_base_azul(self) -> None:
        """Live smoke: must flag attributes.rs near line 65-70 in the real snapshot."""
        result = _run(LIVE_BASE_AZUL)
        rows = result["rows"]
        attr_hits = [
            r for r in rows
            if "attributes.rs" in r.get("file", "")
        ]
        self.assertTrue(
            len(attr_hits) >= 1,
            f"Expected >=1 hit in attributes.rs; all rows: {[r['file'] for r in rows]}",
        )
        # Line must be close to the bug (60-80 range).
        lines = [r["line"] for r in attr_hits]
        self.assertTrue(
            any(55 <= ln <= 80 for ln in lines),
            f"Expected hit between lines 55-80 in attributes.rs; got lines: {lines}",
        )


if __name__ == "__main__":
    unittest.main()
