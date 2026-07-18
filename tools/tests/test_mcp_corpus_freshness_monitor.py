"""Tests for tools/audit/mcp-corpus-freshness-monitor.py (LANE W4.14)."""
from __future__ import annotations

import datetime as _dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "audit" / "mcp-corpus-freshness-monitor.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("mcp_corpus_freshness_monitor", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["mcp_corpus_freshness_monitor"] = module
    spec.loader.exec_module(module)
    return module


mon = _load_module()


def _iso(days_ago: float, now: _dt.datetime) -> str:
    return (now - _dt.timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


class ClassifyTests(unittest.TestCase):
    def test_fresh_aging_stale_bands(self) -> None:
        self.assertEqual(mon._classify(5.0, 14, 30), "FRESH")
        self.assertEqual(mon._classify(14.0, 14, 30), "FRESH")
        self.assertEqual(mon._classify(20.0, 14, 30), "AGING")
        self.assertEqual(mon._classify(45.0, 14, 30), "STALE")

    def test_no_age_is_stale(self) -> None:
        self.assertEqual(mon._classify(None, 14, 30), "STALE")


class AuditSegmentsTests(unittest.TestCase):
    """Build a synthetic registry + repo and verify per-segment verdicts."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.repo = Path(self._td.name)
        self.registry = self.repo / "tools" / "audit" / "etl_miner_registry"
        self.registry.mkdir(parents=True, exist_ok=True)
        self.now = _dt.datetime(2026, 5, 16, 12, 0, 0, tzinfo=_dt.timezone.utc)
        self.now_epoch = self.now.timestamp()

    def _write_entry(self, slug: str, **fields) -> None:
        entry = {"miner_slug": slug, "source_channel": "gh-api"}
        entry.update(fields)
        with (self.registry / f"{slug}.json").open("w") as fh:
            json.dump(entry, fh)

    def _write_subtree(self, rel: str, age_days_record: float) -> None:
        """Create a target subtree with one record whose mtime is age_days old."""
        d = self.repo / rel
        d.mkdir(parents=True, exist_ok=True)
        rec = d / "record.json"
        rec.write_text("{}")
        import os
        ts = self.now_epoch - age_days_record * 86400.0
        os.utime(rec, (ts, ts))

    def test_manifest_is_skipped(self) -> None:
        self._write_entry("alpha")
        (self.registry / "_manifest.json").write_text('{"miner_count": 1}')
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        slugs = {s["miner_slug"] for s in report["segments"]}
        self.assertEqual(slugs, {"alpha"})

    def test_fresh_segment_via_record_mtime(self) -> None:
        self._write_entry("alpha", target_subtree="audit/corpus_tags/tags/alpha")
        self._write_subtree("audit/corpus_tags/tags/alpha", age_days_record=3.0)
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        seg = report["segments"][0]
        self.assertEqual(seg["verdict"], "FRESH")
        self.assertLess(seg["age_days"], 14)

    def test_aging_segment(self) -> None:
        self._write_entry("beta", target_subtree="audit/corpus_tags/tags/beta")
        self._write_subtree("audit/corpus_tags/tags/beta", age_days_record=20.0)
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        self.assertEqual(report["segments"][0]["verdict"], "AGING")

    def test_stale_segment(self) -> None:
        self._write_entry("gamma", target_subtree="audit/corpus_tags/tags/gamma")
        self._write_subtree("audit/corpus_tags/tags/gamma", age_days_record=60.0)
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        seg = report["segments"][0]
        self.assertEqual(seg["verdict"], "STALE")
        self.assertEqual(report["summary"]["stale_count"], 1)
        self.assertTrue(report["summary"]["any_stale"])

    def test_no_age_resolvable_is_stale(self) -> None:
        # No subtree on disk, no resolvable sha -> no age -> STALE.
        self._write_entry("delta", target_subtree="audit/corpus_tags/tags/delta",
                          last_run_commit_sha="deadbeefdeadbeef")
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        seg = report["segments"][0]
        self.assertEqual(seg["verdict"], "STALE")
        self.assertIsNone(seg["age_days"])
        self.assertIn("target-subtree-missing-on-disk", seg["notes"])

    def test_honest_zero_is_fresh_regardless_of_age(self) -> None:
        # honest-zero segment with an ancient record still reports FRESH.
        self._write_entry("epsilon", honest_zero=True,
                          target_subtree="audit/corpus_tags/tags/epsilon")
        self._write_subtree("audit/corpus_tags/tags/epsilon", age_days_record=400.0)
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        seg = report["segments"][0]
        self.assertEqual(seg["verdict"], "FRESH")
        self.assertIn("honest-zero", seg["notes"])

    def test_worst_signal_wins(self) -> None:
        # Record mtime is fresh (3d) but registry sha unresolvable -> the
        # only resolvable signal is the 3d mtime, so FRESH. If BOTH resolve,
        # the older wins; emulate by giving an old subtree.
        self._write_entry("zeta", target_subtree="audit/corpus_tags/tags/zeta")
        self._write_subtree("audit/corpus_tags/tags/zeta", age_days_record=50.0)
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        self.assertEqual(report["segments"][0]["verdict"], "STALE")

    def test_upstream_mapping_per_channel(self) -> None:
        self._write_entry("a1", source_channel="gh-api")
        self._write_entry("a2", source_channel="commit-history")
        self._write_entry("a3", source_channel="pdf-listing")
        self._write_entry("a4", source_channel="weird-channel")
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        by_slug = {s["miner_slug"]: s for s in report["segments"]}
        self.assertIn("gh api", by_slug["a1"]["repull_guidance"])
        self.assertIn("git log", by_slug["a2"]["repull_guidance"])
        self.assertIn("PDF", by_slug["a3"]["repull_guidance"])
        self.assertIn("unknown", by_slug["a4"]["upstream_source"])

    def test_repull_command_prefers_makefile_target(self) -> None:
        self._write_entry("m1", makefile_target="hackerman-etl-from-m1",
                          tool_path="tools/x.py")
        self._write_entry("m2", tool_path="tools/y.py")
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        by_slug = {s["miner_slug"]: s for s in report["segments"]}
        self.assertEqual(by_slug["m1"]["repull_command"], "make hackerman-etl-from-m1")
        self.assertEqual(by_slug["m2"]["repull_command"], "tools/y.py")

    def test_summary_schema_and_counts(self) -> None:
        self._write_entry("s1", target_subtree="audit/corpus_tags/tags/s1")
        self._write_subtree("audit/corpus_tags/tags/s1", age_days_record=2.0)
        self._write_entry("s2", target_subtree="audit/corpus_tags/tags/s2")
        self._write_subtree("audit/corpus_tags/tags/s2", age_days_record=60.0)
        report = mon.audit_segments(
            repo_root=self.repo, registry_dir=self.registry, now_epoch=self.now_epoch
        )
        s = report["summary"]
        self.assertEqual(s["schema"], "auditooor.mcp_corpus_freshness.v1")
        self.assertEqual(s["segment_count"], 2)
        self.assertEqual(s["fresh_count"], 1)
        self.assertEqual(s["stale_count"], 1)
        self.assertIn("vault_corpus_search", s["corpus_backed_callables"])


class LiveRegistryTests(unittest.TestCase):
    """Smoke test against the real in-repo ETL registry."""

    def test_real_registry_audits_cleanly(self) -> None:
        report = mon.audit_segments()
        self.assertEqual(report["schema"], "auditooor.mcp_corpus_freshness.v1")
        self.assertGreater(report["summary"]["segment_count"], 0)
        for seg in report["segments"]:
            self.assertIn(seg["verdict"], {"FRESH", "AGING", "STALE"})
            self.assertIn("repull_guidance", seg)


if __name__ == "__main__":
    unittest.main()
