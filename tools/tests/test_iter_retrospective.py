#!/usr/bin/env python3
"""iter9 T3 — offline tests for tools/iter-retrospective.py.

Tests use `tempfile.TemporaryDirectory()` sandboxes for the fixtures.
One test reads the real `docs/LOOP_ITER_001_RESULTS.md` from the repo to
pin the extractor against actual iter-doc shape. Tool is invoked as a
subprocess, exactly as the operator or `make iter-retrospective` target
would invoke it.

Offline. Stdlib only. No network. No writes outside the tempdir (except
reads of the repo `docs/` tree in the real-data test).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "iter-retrospective.py"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
    )


class IterRetrospectiveTests(unittest.TestCase):
    def test_parses_iter1_results_correctly(self) -> None:
        """Reads the real docs/LOOP_ITER_001_RESULTS.md and asserts
        tests_green=171 and pending_rows=0-or-question (per spec pending
        for iter1 is 0 implicit OR ? honest — the real file omits a
        pending row; we accept either)."""
        real_docs = ROOT / "docs"
        # Restrict glob to iter1 only so we get a single-row table.
        r = _run(
            "--results-dir",
            str(real_docs),
            "--pattern",
            "LOOP_ITER_001_RESULTS.md",
            "--json",
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        payload = json.loads(r.stdout)
        self.assertIn("iterations", payload)
        self.assertEqual(len(payload["iterations"]), 1)
        row = payload["iterations"][0]
        self.assertEqual(row["iter"], 1)
        self.assertEqual(row["tests_green"], "171")
        # iter1's dossier does NOT carry a "Pending ledger rows" table
        # row (the concept entered the format in iter3). Per spec, unknown
        # falls back to `?` — we assert that rather than fabricating 0.
        self.assertEqual(row["pending_rows"], "?")
        self.assertEqual(row["forced_findings"], "0")

    def test_handles_missing_file_gracefully(self) -> None:
        """Empty directory -> emits table with header only, exit 0, and a
        warning to stderr. No crash."""
        with tempfile.TemporaryDirectory() as td:
            r = _run("--results-dir", td)
            self.assertEqual(r.returncode, 0, msg=r.stderr)
            self.assertIn("Iter", r.stdout)
            self.assertIn("Tests green", r.stdout)
            # Only header + separator rows in body (2 lines + trailing
            # newline) — no data rows.
            body_lines = [
                ln for ln in r.stdout.splitlines() if ln.startswith("|")
            ]
            self.assertEqual(len(body_lines), 2)
            self.assertIn("no files matched", r.stderr)

    def test_json_mode_emits_parseable_json(self) -> None:
        """--json against the real docs/ tree yields valid JSON with an
        `iterations` key containing a list of dicts."""
        real_docs = ROOT / "docs"
        r = _run("--results-dir", str(real_docs), "--json")
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        payload = json.loads(r.stdout)  # raises on invalid JSON -> fails test
        self.assertIn("iterations", payload)
        self.assertIsInstance(payload["iterations"], list)
        self.assertGreater(len(payload["iterations"]), 0)
        for it in payload["iterations"]:
            self.assertIsInstance(it, dict)
            self.assertIn("iter", it)
            self.assertIn("tests_green", it)
            self.assertIn("pending_rows", it)
            self.assertIn("forced_findings", it)
            self.assertIn("notable", it)

    def test_iter2_pending_rows_backfilled_to_zero_via_secondary_parse(self) -> None:
        """iter10 T5: iter2's dossier contains `| Ledger rows added | 0 | 0 |`
        in its Totals table AND `0 ledger rows` in its commit-log. The
        secondary parser must recognize one of these explicit-zero forms
        and produce `0` rather than `?`. Cited match must appear on
        stderr so the backfill is never silent/fabricated."""
        real_docs = ROOT / "docs"
        r = _run(
            "--results-dir",
            str(real_docs),
            "--pattern",
            "LOOP_ITER_002_RESULTS.md",
            "--json",
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        payload = json.loads(r.stdout)
        self.assertEqual(len(payload["iterations"]), 1)
        row = payload["iterations"][0]
        self.assertEqual(row["iter"], 2)
        self.assertEqual(row["tests_green"], "175")
        self.assertEqual(row["pending_rows"], "0")  # backfilled, not `?`
        # Cited match line on stderr — operator must be able to audit.
        self.assertIn("secondary parse matched", r.stderr)
        self.assertIn("LOOP_ITER_002_RESULTS.md", r.stderr)

    def test_secondary_parse_does_not_fabricate_nonzero_values(self) -> None:
        """Hard-negative: if a doc has no explicit pending-rows zero
        statement AND no totals-table row, the secondary parser must
        return `?`, NEVER invent a number. Even if the doc contains
        unrelated numbers (e.g. 'processed 42 items'), the secondary
        parser must not latch on. This test is the anti-fabrication
        guardrail for iter10 T5."""
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td) / "LOOP_ITER_099_RESULTS.md"
            fixture.write_text(
                "# Iteration 099 — silent on ledger rows\n"
                "\n"
                "## What landed\n"
                "\n"
                "Agent processed 42 drafts and 7 contracts. No ledger\n"
                "table, no pending-rows prose. Unrelated numbers present.\n"
                "\n"
                "| Metric | Value |\n"
                "|---|---:|\n"
                "| Drafts processed | 42 |\n"
                "| Contracts scanned | 7 |\n"
                "\n"
                "## Totals\n"
                "\n"
                "| Metric | Value |\n"
                "|---|---:|\n"
                "| Offline tests | **300 tests / 0 failures / 0 skipped** |\n"
                "| Forced / fabricated findings | 0 |\n",
                encoding="utf-8",
            )
            r = _run("--results-dir", td, "--json")
            self.assertEqual(r.returncode, 0, msg=r.stderr)
            payload = json.loads(r.stdout)
            self.assertEqual(len(payload["iterations"]), 1)
            row = payload["iterations"][0]
            self.assertEqual(row["iter"], 99)
            # Primary parse: no 'pending ledger' row -> ? .
            # Secondary parse: no explicit-zero phrase -> ? (NOT "0"!).
            self.assertEqual(row["pending_rows"], "?")
            # tests_green should still parse cleanly (independent path).
            self.assertEqual(row["tests_green"], "300")
            # Forced findings row IS present and reads 0.
            self.assertEqual(row["forced_findings"], "0")
            # Stderr must record the honest miss, NOT a bogus "matched" line.
            self.assertIn("leaving as `?`", r.stderr)
            self.assertNotIn("secondary parse matched", r.stderr)

    def test_ambiguous_format_emits_question_mark(self) -> None:
        """A corrupted/non-matching results doc -> all extractable fields
        fall back to '?' with a warning on stderr; tool exits 0 and does
        not crash."""
        with tempfile.TemporaryDirectory() as td:
            junk = Path(td) / "LOOP_ITER_042_RESULTS.md"
            junk.write_text(
                "# Iteration 042 — corrupted fixture\n"
                "\n"
                "This file intentionally contains no totals table, no\n"
                "pending-ledger row, no Forced / fabricated findings row,\n"
                "and no headline-style section. It is a negative control.\n",
                encoding="utf-8",
            )
            r = _run("--results-dir", td, "--json")
            self.assertEqual(r.returncode, 0, msg=r.stderr)
            payload = json.loads(r.stdout)
            self.assertEqual(len(payload["iterations"]), 1)
            row = payload["iterations"][0]
            self.assertEqual(row["iter"], 42)
            self.assertEqual(row["tests_green"], "?")
            self.assertEqual(row["pending_rows"], "?")
            self.assertEqual(row["forced_findings"], "?")
            self.assertEqual(row["notable"], "?")
            # Warning lines about each missing field must appear on stderr.
            self.assertIn("LOOP_ITER_042_RESULTS.md", r.stderr)


if __name__ == "__main__":
    unittest.main()
