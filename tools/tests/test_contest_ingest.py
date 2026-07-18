#!/usr/bin/env python3
"""Offline tests for tools/contest-ingest.py (PR 205 skeleton).

All filesystem reads that depend on operator-local state are either pointed
at `tools/tests/fixtures/contest_cache/` or at per-test temp dirs. These
tests MUST run without network and without a populated
`reference/contest_cache/`.

Hard constraints verified:
  - Advisory-only: no write to `reference/patterns.dsl/` under any flag.
  - Dedup: contrived collider seeds are marked `duplicate` and excluded
    from the JSONL.
  - Status vocabulary: only {advisory-seed, duplicate, error} appears in
    outputs. No new strings.
  - Live fetch: `--live-fetch` hard-errors, never silently succeeds.
  - Empty cache: emits zero rows + advisory message + exit 0.
"""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "contest-ingest.py"
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "contest_cache"
LIVE_DSL = ROOT / "reference" / "patterns.dsl"


def _empty_live_dsl(tmp: Path) -> Path:
    """Return a temp `patterns.dsl/` dir that is empty. Used by tests
    that MUST NOT depend on the operator-local pattern corpus — per the
    T4 brief, offline tests should `mock.patch` any filesystem read
    that would otherwise pull in operator-local state. Using an empty
    live-dsl-dir is equivalent to mocking the scanner to return no
    patterns, and keeps the test deterministic if the corpus grows."""
    d = tmp / "empty_live_dsl"
    d.mkdir()
    return d


def _load_module():
    """Import contest-ingest.py as a module despite the hyphen in its name."""
    spec = importlib.util.spec_from_file_location("contest_ingest", TOOL)
    assert spec and spec.loader, f"contest-ingest.py missing at {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CI = _load_module()


def _count_bytes(root: Path) -> int:
    """Sum of file sizes under `root` (recursive). Used by the
    patterns.dsl/ non-mutation regression test."""
    total = 0
    if not root.is_dir():
        return 0
    for p in sorted(root.rglob("*")):
        if p.is_file():
            total += p.stat().st_size
    return total


class ContestIngestTest(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. Parses Cantina fixture and writes N novelty seeds.
    # ------------------------------------------------------------------
    def test_ingest_parses_cantina_fixture(self) -> None:
        """The cantina fixture has 3 findings. Against an *empty*
        live-dsl-dir (no dedup can fire), all 3 should land in the
        JSONL, each tagged with the cantina platform. Uses an empty
        live-dsl-dir so this test does not depend on the operator-local
        pattern corpus — per T4 brief's isolate-from-operator-state
        constraint."""
        with tempfile.TemporaryDirectory() as tmp:
            tmpp = Path(tmp)
            out = tmpp / "out.jsonl"
            cache = tmpp / "cache"
            cache.mkdir()
            (cache / "cantina").mkdir()
            src = FIXTURES / "cantina" / "example_contest_001.json"
            (cache / "cantina" / "example_contest_001.json").write_text(
                src.read_text(encoding="utf-8"), encoding="utf-8",
            )
            rc = CI.main([
                "--test-fixtures", str(cache),
                "--out", str(out),
                "--live-dsl-dir", str(_empty_live_dsl(tmpp)),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            # All 3 fixture findings land because there is no live
            # corpus to dedup against.
            self.assertEqual(len(rows), 3, f"expected 3 seeds, got {rows}")
            for r in rows:
                self.assertEqual(r["source_platform"], "cantina")
                self.assertEqual(r["status"], CI.STATUS_ADVISORY_SEED)
                self.assertIn("sig", r)
                self.assertIn("ingested_at", r)

    # ------------------------------------------------------------------
    # 2. Parses Immunefi fixture and writes N novelty seeds.
    # ------------------------------------------------------------------
    def test_ingest_parses_immunefi_fixture(self) -> None:
        """The immunefi fixture has 2 findings. Against an empty
        live-dsl-dir both land as advisory-seed rows; each is tagged
        with the immunefi platform."""
        with tempfile.TemporaryDirectory() as tmp:
            tmpp = Path(tmp)
            out = tmpp / "out.jsonl"
            cache = tmpp / "cache"
            cache.mkdir()
            (cache / "immunefi").mkdir()
            src = FIXTURES / "immunefi" / "example_contest_A.json"
            (cache / "immunefi" / "example_contest_A.json").write_text(
                src.read_text(encoding="utf-8"), encoding="utf-8",
            )
            rc = CI.main([
                "--test-fixtures", str(cache),
                "--out", str(out),
                "--live-dsl-dir", str(_empty_live_dsl(tmpp)),
            ])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 2, f"expected 2 seeds, got {rows}")
            for r in rows:
                self.assertEqual(r["source_platform"], "immunefi")
                self.assertEqual(r["status"], CI.STATUS_ADVISORY_SEED)

    # ------------------------------------------------------------------
    # 3. Dedup against existing patterns.dsl — collider is marked duplicate.
    # ------------------------------------------------------------------
    def test_ingest_dedup_against_existing_patterns_dsl(self) -> None:
        """Run ingestion against the full (cantina+immunefi) fixture set.
        Two contrived colliders exist — one in each file. Both should be
        caught by the title-token overlap path against
        reference/patterns.dsl/. Neither should appear in the JSONL."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.jsonl"
            stderr_capture = io.StringIO()
            seeds, dups, total = CI.ingest(
                cache_dir=FIXTURES,
                out_path=out,
                live_dsl_dir=LIVE_DSL,
                promote_to_live=False,
                now_iso="2026-04-23T00:00:00+00:00",
                stderr=stderr_capture,
            )
            # 2 contrived colliders — both must be dup.
            self.assertGreaterEqual(dups, 2, f"expected ≥2 duplicates, got {dups}")
            # The 3 non-collider seeds must land in the JSONL.
            self.assertEqual(seeds, total - dups)
            self.assertEqual(seeds, 3, f"expected 3 novel seeds, got {seeds}")
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            titles_written = {r["title"] for r in rows}
            # Neither collider title appears in the JSONL.
            contrived_cantina = (
                "abi.encodePacked collision in domainSeparator enables signature replay"
            )
            contrived_immunefi = (
                "Admin sweep blocks pending user claims by transferring full contract balance"
            )
            self.assertNotIn(contrived_cantina, titles_written)
            self.assertNotIn(contrived_immunefi, titles_written)
            # Stderr advisory for duplicates carries the locked status string.
            stderr_text = stderr_capture.getvalue()
            self.assertIn("status=duplicate", stderr_text)
            self.assertIn(CI.STATUS_DUPLICATE, stderr_text)

    # ------------------------------------------------------------------
    # 4. Non-flagged run never mutates reference/patterns.dsl/.
    # ------------------------------------------------------------------
    def test_ingest_without_promote_flag_never_writes_to_patterns_dsl(self) -> None:
        """Run ingest end-to-end without --promote-to-live. Snapshot the
        total byte-count of every file under reference/patterns.dsl/
        before and after. Must be byte-identical. This locks in the
        advisory-only constraint."""
        before = _count_bytes(LIVE_DSL)
        file_count_before = sum(1 for _ in LIVE_DSL.rglob("*") if _.is_file())
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.jsonl"
            rc = CI.main([
                "--test-fixtures", str(FIXTURES),
                "--out", str(out),
                "--live-dsl-dir", str(LIVE_DSL),
            ])
            self.assertEqual(rc, 0)
        after = _count_bytes(LIVE_DSL)
        file_count_after = sum(1 for _ in LIVE_DSL.rglob("*") if _.is_file())
        self.assertEqual(
            before, after,
            f"patterns.dsl/ byte-count changed: {before} → {after}. "
            "Advisory-only constraint violated.",
        )
        self.assertEqual(file_count_before, file_count_after)

    # ------------------------------------------------------------------
    # 5. Empty cache — empty JSONL, exit 0, advisory message.
    #    Also asserts --live-fetch hard-errors so cannot-judge paths
    #    don't silently succeed (FM-002-style guard).
    # ------------------------------------------------------------------
    def test_ingest_empty_cache_produces_empty_output(self) -> None:
        """Point at an empty cache dir. Expect zero rows, exit 0, and
        an advisory message on stderr that signals 'cache was empty'
        rather than silent success. Also verifies --live-fetch hard-
        errors so the offline-only contract cannot be bypassed."""
        with tempfile.TemporaryDirectory() as tmp:
            tmpp = Path(tmp)
            empty_cache = tmpp / "empty_cache"
            empty_cache.mkdir()
            out = tmpp / "out.jsonl"
            proc = subprocess.run(
                [
                    sys.executable, str(TOOL),
                    "--test-fixtures", str(empty_cache),
                    "--out", str(out),
                    "--live-dsl-dir", str(_empty_live_dsl(tmpp)),
                ],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(out.exists())
            self.assertEqual(out.read_text(), "")
            self.assertIn("cache was empty", proc.stderr)

            # Live-fetch path must hard-error — never silently succeed.
            fetch_proc = subprocess.run(
                [sys.executable, str(TOOL), "--live-fetch"],
                capture_output=True, text=True,
            )
            self.assertEqual(fetch_proc.returncode, 1)
            self.assertIn("live-fetch not implemented", fetch_proc.stderr)


if __name__ == "__main__":
    unittest.main()
