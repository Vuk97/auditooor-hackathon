"""Tests for tools/deep-crawler-staleness-check.py."""
from __future__ import annotations

import datetime as _dt
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "deep-crawler-staleness-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("deep_crawler_staleness_check", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["deep_crawler_staleness_check"] = module
    spec.loader.exec_module(module)
    return module


staleness = _load_module()


def _epoch(days_ago: float, *, now: float | None = None) -> float:
    now = now or _dt.datetime(2026, 5, 7, 12, 0, 0, tzinfo=_dt.timezone.utc).timestamp()
    return now - days_ago * 86400.0


class StalenessAuditTests(unittest.TestCase):
    """Audit core: build a synthetic vault and verify classification."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.vault = Path(self._td.name)
        # Pre-create vault subdirs so vault_path resolves.
        for meta in staleness.SECTION_REGISTRY.values():
            (self.vault / meta["vault_subdir"]).mkdir(parents=True, exist_ok=True)
        self.now = _dt.datetime(2026, 5, 7, 12, 0, 0, tzinfo=_dt.timezone.utc).timestamp()

    def _write_sync_state(self, mapping: dict[str, float]) -> None:
        path = self.vault / ".deep_sync.json"
        with path.open("w") as fh:
            json.dump(mapping, fh)

    def test_all_fresh(self) -> None:
        """All sections within stale_days threshold → status=fresh, exit 0."""
        sync = {
            "claude-memory": _epoch(1, now=self.now),
            "codex-memory": _epoch(2, now=self.now),
            "routines": _epoch(1, now=self.now),
            "commits": _epoch(0.5, now=self.now),
            "prs": _epoch(1, now=self.now),
            "tools-api": _epoch(3, now=self.now),
            "make-targets": _epoch(1, now=self.now),
            "workspaces/foo": _epoch(2, now=self.now),
            "errors/run": _epoch(1, now=self.now),
        }
        self._write_sync_state(sync)
        report = staleness.audit_sections(self.vault, now_epoch=self.now)
        self.assertEqual(report["summary"]["fresh_count"], 9)
        self.assertEqual(report["summary"]["stale_count"], 0)
        self.assertEqual(report["summary"]["stale_hard_count"], 0)
        self.assertEqual(report["summary"]["missing_count"], 0)
        self.assertFalse(report["summary"]["any_stale"])

    def test_mixed_fresh_stale_missing(self) -> None:
        """Mixed mtimes produce expected per-section status."""
        sync = {
            "claude-memory": _epoch(1, now=self.now),    # fresh
            "codex-memory": _epoch(18, now=self.now),    # stale (>14)
            "routines": _epoch(31, now=self.now),        # stale-hard (>30)
            "commits": _epoch(2, now=self.now),          # fresh
            "prs": _epoch(2, now=self.now),              # fresh
            "tools-api": _epoch(2, now=self.now),        # fresh
            "make-targets": _epoch(2, now=self.now),     # fresh
            # workspaces — none → missing (no mtime fallback either)
            # errors — none → missing
        }
        self._write_sync_state(sync)
        report = staleness.audit_sections(self.vault, now_epoch=self.now)
        by_name = {s["section"]: s for s in report["sections"]}
        self.assertEqual(by_name["claude-memory"]["status"], "fresh")
        self.assertEqual(by_name["codex-memory"]["status"], "stale")
        self.assertEqual(by_name["routines"]["status"], "stale-hard")
        self.assertEqual(by_name["workspaces"]["status"], "missing")
        self.assertEqual(by_name["errors"]["status"], "missing")
        self.assertTrue(report["summary"]["any_stale"])
        self.assertEqual(report["summary"]["stale_count"], 1)
        self.assertEqual(report["summary"]["stale_hard_count"], 1)
        self.assertEqual(report["summary"]["missing_count"], 2)

    def test_workspaces_aggregation(self) -> None:
        """workspaces/* keys aggregate by max."""
        sync = {
            "workspaces/alpha": _epoch(40, now=self.now),
            "workspaces/beta": _epoch(3, now=self.now),  # max → fresh
            "workspaces/gamma": _epoch(20, now=self.now),
        }
        self._write_sync_state(sync)
        report = staleness.audit_sections(self.vault, now_epoch=self.now)
        ws = next(s for s in report["sections"] if s["section"] == "workspaces")
        self.assertEqual(ws["status"], "fresh")
        self.assertLess(ws["age_days"], 14)

    def test_errors_aggregation(self) -> None:
        """errors/* keys aggregate by max."""
        sync = {
            "errors/run": _epoch(50, now=self.now),
            "errors/queue_a": _epoch(10, now=self.now),  # max → fresh
        }
        self._write_sync_state(sync)
        report = staleness.audit_sections(self.vault, now_epoch=self.now)
        err = next(s for s in report["sections"] if s["section"] == "errors")
        self.assertEqual(err["status"], "fresh")

    def test_mtime_fallback_when_sync_state_absent(self) -> None:
        """If .deep_sync.json is missing, .md mtimes drive freshness."""
        # No sync state file written.
        # Touch a fresh .md in claude subdir; leave others empty → missing.
        fresh_md = self.vault / "external-memory" / "claude" / "abc.md"
        fresh_md.parent.mkdir(parents=True, exist_ok=True)
        fresh_md.write_text("hello")
        # Set mtime to ~2 days ago.
        target = _epoch(2, now=self.now)
        os.utime(fresh_md, (target, target))

        report = staleness.audit_sections(self.vault, now_epoch=self.now)
        by_name = {s["section"]: s for s in report["sections"]}
        self.assertEqual(by_name["claude-memory"]["status"], "fresh")
        self.assertEqual(by_name["claude-memory"]["last_sync_source"], "mtime_fallback")
        # Other sections — empty dirs → missing.
        self.assertEqual(by_name["codex-memory"]["status"], "missing")
        self.assertEqual(by_name["codex-memory"]["last_sync_source"], "missing")

    def test_schema_constant(self) -> None:
        """Schema string is the documented canonical value."""
        self.assertEqual(staleness.SCHEMA, "auditooor.deep_crawler_staleness.v1")
        report = staleness.audit_sections(self.vault, now_epoch=self.now)
        self.assertEqual(report["schema"], "auditooor.deep_crawler_staleness.v1")
        self.assertEqual(report["summary"]["schema"], "auditooor.deep_crawler_staleness.v1")

    def test_main_advisory_exit_zero_when_stale(self) -> None:
        """Default (advisory) mode never fails."""
        sync = {
            "claude-memory": _epoch(31, now=self.now),
        }
        self._write_sync_state(sync)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            out_path = tmp.name
        self.addCleanup(lambda: os.unlink(out_path) if os.path.exists(out_path) else None)
        rc = staleness.main([
            "--vault-dir", str(self.vault),
            "--out", out_path,
        ])
        self.assertEqual(rc, 0, "advisory default must always exit 0")
        with open(out_path) as fh:
            data = json.load(fh)
        self.assertTrue(data["summary"]["any_stale"])

    def test_main_strict_exit_one_when_stale(self) -> None:
        """--strict flips exit code when any section is stale or missing."""
        sync = {
            "claude-memory": _epoch(31, now=self.now),
        }
        self._write_sync_state(sync)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            out_path = tmp.name
        self.addCleanup(lambda: os.unlink(out_path) if os.path.exists(out_path) else None)
        rc = staleness.main([
            "--vault-dir", str(self.vault),
            "--out", out_path,
            "--strict",
        ])
        self.assertEqual(rc, 1)


class RegistryShapeTests(unittest.TestCase):
    """Static sanity: SECTION_REGISTRY mirrors deep-crawler ALL_SECTIONS."""

    def test_registry_covers_all_deep_crawler_sections(self) -> None:
        # Inline-load deep-crawler so the test does not depend on its imports
        # succeeding (it imports yaml etc. — load only the constant we need).
        text = (REPO_ROOT / "tools" / "memory-deep-crawler.py").read_text()
        # Grab the literal list line.
        marker = "ALL_SECTIONS = ["
        idx = text.find(marker)
        self.assertGreater(idx, 0, "ALL_SECTIONS not found in memory-deep-crawler.py")
        # Take the slice up to the first close-bracket after the marker.
        slice_ = text[idx:idx + 400]
        end = slice_.find("]")
        self.assertGreater(end, 0)
        literal = slice_[len(marker):end]
        names = [tok.strip().strip("\"',") for tok in literal.split(",") if tok.strip().strip("\"',")]
        self.assertGreaterEqual(len(names), 1)
        for name in names:
            self.assertIn(
                name, staleness.SECTION_REGISTRY,
                f"deep-crawler section {name!r} missing from staleness SECTION_REGISTRY",
            )

    def test_cadence_values_are_valid(self) -> None:
        valid = {"daily", "weekly", "on-event"}
        for meta in staleness.SECTION_REGISTRY.values():
            self.assertIn(meta["cadence"], valid)


if __name__ == "__main__":
    unittest.main()
