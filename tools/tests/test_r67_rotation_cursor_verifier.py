# r36-rebuttal: LIFT-26 lane registered in .auditooor/agent_pathspec.json (lane-LIFT-26-R67)
"""Tests for tools/r67-rotation-cursor-verifier.py (LIFT-26 / R67).

Coverage:
 1. PASS: fresh rotation entry + no shrinkage -> pass-fresh-rotation-and-stable
 2. WARN: no rotation log -> warn-no-rotation-log
 3. FAIL: file shrunk >50% since last log entry -> fail-shrinkage-over-50pct...
 4. WARN: rotation log entry too old (stale) -> warn-stale-rotation-log
 5. PASS: shrinkage below threshold (e.g. 20%) -> pass-fresh-rotation-and-stable
 6. ERROR: target file not found -> error verdict
 7. walk_corpus enumerates only known corpus extensions, skips .bak / .tmp
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))

from tools.lib.atomic_corpus_writer import (  # noqa: E402
    atomic_write_corpus_file,
    rotation_log_path,
)

# Load r67-rotation-cursor-verifier as a module (the script's filename uses
# hyphens, so we can't `import tools.r67-rotation-cursor-verifier`).
_VERIFIER_PATH = _REPO / "tools" / "r67-rotation-cursor-verifier.py"
_spec = importlib.util.spec_from_file_location(
    "r67_rotation_cursor_verifier", _VERIFIER_PATH
)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["r67_rotation_cursor_verifier"] = _mod
_spec.loader.exec_module(_mod)
verify_file = _mod.verify_file
walk_corpus = _mod.walk_corpus


class VerifierTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="r67-verify-"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_fresh_rotation_no_shrinkage_passes(self):
        p = self.tmpdir / "corpus.jsonl"
        atomic_write_corpus_file(p, '{"a":1}\n' * 100)  # ~800 bytes
        atomic_write_corpus_file(p, '{"a":2}\n' * 100)  # ~800 bytes (no shrink)
        result = verify_file(p, freshness_hours=24, shrinkage_ratio=0.5)
        self.assertEqual(result["verdict"], "pass-fresh-rotation-and-stable")
        self.assertEqual(result["log_entries"], 2)
        self.assertIsNotNone(result["last_log_age_hours"])
        self.assertLess(result["last_log_age_hours"], 1.0)

    def test_no_rotation_log_warns(self):
        p = self.tmpdir / "corpus.jsonl"
        p.write_text("seed content not via atomic writer\n")
        result = verify_file(p, freshness_hours=24, shrinkage_ratio=0.5)
        self.assertEqual(result["verdict"], "warn-no-rotation-log")
        self.assertEqual(result["log_entries"], 0)

    def test_shrinkage_above_threshold_fails(self):
        """Simulate the LIFT-9 2.0M -> 216K shrinkage pattern."""
        p = self.tmpdir / "corpus.jsonl"
        # Write large content via atomic writer (logged).
        atomic_write_corpus_file(p, "x" * 2_000_000)
        # Out-of-band truncation: simulating a non-atomic write that
        # silently shrinks the file (the LIFT-9 failure mode). Note: this
        # bypasses atomic_write_corpus_file, so no new rotation_log entry.
        p.write_text("x" * 216_000)
        result = verify_file(p, freshness_hours=24, shrinkage_ratio=0.5)
        self.assertEqual(result["verdict"], "fail-shrinkage-over-50pct-no-log-entry")
        self.assertGreater(result["shrinkage_pct"], 50.0)

    def test_stale_rotation_log_warns(self):
        p = self.tmpdir / "corpus.jsonl"
        atomic_write_corpus_file(p, "v1\n")
        # Manually overwrite the rotation log entry's ts to far in the past
        # (simulating a freshness violation).
        log_path = rotation_log_path(p)
        entries = log_path.read_text().splitlines()
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        record = json.loads(entries[0])
        record["ts"] = old_ts
        log_path.write_text(json.dumps(record, sort_keys=True) + "\n")
        result = verify_file(p, freshness_hours=24, shrinkage_ratio=0.5)
        self.assertEqual(result["verdict"], "warn-stale-rotation-log")
        self.assertGreater(result["last_log_age_hours"], 24)

    def test_minor_shrinkage_below_threshold_passes(self):
        p = self.tmpdir / "corpus.jsonl"
        atomic_write_corpus_file(p, "x" * 1000)
        # Out-of-band 20% shrinkage (still fresh log, but below 50% threshold).
        p.write_text("x" * 800)
        result = verify_file(p, freshness_hours=24, shrinkage_ratio=0.5)
        # 20% shrinkage < 50% threshold -> pass.
        self.assertEqual(result["verdict"], "pass-fresh-rotation-and-stable")
        self.assertAlmostEqual(result["shrinkage_pct"], 20.0, places=1)

    def test_file_not_found_errors(self):
        result = verify_file(
            self.tmpdir / "does-not-exist.jsonl",
            freshness_hours=24,
            shrinkage_ratio=0.5,
        )
        self.assertEqual(result["verdict"], "error")
        self.assertEqual(result["reason"], "file-not-found")

    def test_walk_corpus_extension_and_skip_logic(self):
        # Lay out a fake workspace with derived/ dir + various files.
        derived = self.tmpdir / "audit" / "corpus_tags" / "derived"
        derived.mkdir(parents=True)
        (derived / "good.jsonl").write_text("row\n")
        (derived / "also-good.json").write_text("{}\n")
        # Skip files:
        (derived / "good.jsonl.rotation_log.jsonl").write_text("{}\n")
        (derived / "good.jsonl.bak.20260526T120000Z.deadbeef").write_text("backup\n")
        (derived / "good.jsonl.tmp.xyz").write_text("tmp\n")
        (derived / "readme.md").write_text("not a corpus file\n")

        out = walk_corpus(self.tmpdir)
        names = {p.name for p in out}
        self.assertIn("good.jsonl", names)
        self.assertIn("also-good.json", names)
        # Skipped names:
        self.assertNotIn("good.jsonl.rotation_log.jsonl", names)
        self.assertNotIn("good.jsonl.bak.20260526T120000Z.deadbeef", names)
        self.assertNotIn("good.jsonl.tmp.xyz", names)
        self.assertNotIn("readme.md", names)


if __name__ == "__main__":
    unittest.main()
