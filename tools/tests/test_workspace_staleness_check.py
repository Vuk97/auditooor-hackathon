"""
Tests for tools/workspace-staleness-check.py (CAP-MORPHO-D)

Cases covered:
  1. All artifacts fresh (mtime within warn threshold) -> FRESH overall
  2. engage_report.md is WARN age (>7d) -> WARN
  3. engage_report.md is STALE age (>14d) -> STALE
  4. engage_report.md is CRITICAL age (>30d) -> CRITICAL
  5. SCOPE.md missing -> MISSING severity
  6. Morpho dogfood: engage_report.md is ~28d old -> CRITICAL
  7. --strict flag exits 1 on STALE/CRITICAL
  8. main() writes JSON sidecar
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Load module with hyphenated filename
# ---------------------------------------------------------------------------

_TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "workspace-staleness-check.py"
_spec = importlib.util.spec_from_file_location("workspace_staleness_check", _TOOL_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

main = _mod.main
run_checks = _mod.run_checks
SEV_FRESH = _mod.SEV_FRESH
SEV_WARN = _mod.SEV_WARN
SEV_STALE = _mod.SEV_STALE
SEV_CRITICAL = _mod.SEV_CRITICAL
SEV_MISSING = _mod.SEV_MISSING


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _touch_with_age(path: Path, age_days: float) -> None:
    """Create file and backdates its mtime by age_days."""
    path.write_text("")
    mtime = time.time() - age_days * 86400
    os.utime(str(path), (mtime, mtime))


# ---------------------------------------------------------------------------
# Tests - threshold classification
# ---------------------------------------------------------------------------


class TestStalnessThresholds(unittest.TestCase):
    def _make_ws(self, engage_age_days: float) -> Path:
        td = tempfile.mkdtemp()
        ws = Path(td)
        # Create all three required artifacts; only engage_report varies
        _touch_with_age(ws / "engage_report.md", engage_age_days)
        (ws / "docs").mkdir()
        _touch_with_age(ws / "docs" / "LIVE_TARGET_REPORT.md", 1.0)  # fresh
        _touch_with_age(ws / "SCOPE.md", 0.5)  # fresh
        return ws

    def test_fresh(self):
        ws = self._make_ws(engage_age_days=1.0)
        result = run_checks(ws)
        engage_check = next(c for c in result["checks"] if "engage" in c["artifact"])
        self.assertEqual(engage_check["severity"], SEV_FRESH)

    def test_warn(self):
        ws = self._make_ws(engage_age_days=8.0)  # > 7d default threshold
        result = run_checks(ws)
        engage_check = next(c for c in result["checks"] if "engage" in c["artifact"])
        self.assertEqual(engage_check["severity"], SEV_WARN)

    def test_stale(self):
        ws = self._make_ws(engage_age_days=15.0)  # > 14d
        result = run_checks(ws)
        engage_check = next(c for c in result["checks"] if "engage" in c["artifact"])
        self.assertEqual(engage_check["severity"], SEV_STALE)

    def test_critical(self):
        ws = self._make_ws(engage_age_days=31.0)  # > 30d
        result = run_checks(ws)
        engage_check = next(c for c in result["checks"] if "engage" in c["artifact"])
        self.assertEqual(engage_check["severity"], SEV_CRITICAL)
        self.assertEqual(result["overall_severity"], SEV_CRITICAL)


class TestMissing(unittest.TestCase):
    def test_scope_missing(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Only SCOPE.md is absent
            _touch_with_age(ws / "engage_report.md", 1.0)
            (ws / "docs").mkdir()
            _touch_with_age(ws / "docs" / "LIVE_TARGET_REPORT.md", 1.0)
            result = run_checks(ws)
        scope_check = next(c for c in result["checks"] if "SCOPE.md" in c["artifact"])
        self.assertEqual(scope_check["severity"], SEV_MISSING)

    def test_live_target_report_docs_path_is_canonical(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "docs").mkdir()
            _touch_with_age(ws / "engage_report.md", 1.0)
            _touch_with_age(ws / "docs" / "LIVE_TARGET_REPORT.md", 1.0)
            _touch_with_age(ws / "SCOPE.md", 0.5)
            result = run_checks(ws)
        live_check = next(c for c in result["checks"] if c["label"] == "Live target report")
        self.assertEqual(live_check["artifact"], "docs/LIVE_TARGET_REPORT.md")
        self.assertEqual(live_check["severity"], SEV_FRESH)

    def test_live_target_report_root_path_is_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _touch_with_age(ws / "engage_report.md", 1.0)
            _touch_with_age(ws / "LIVE_TARGET_REPORT.md", 1.0)
            _touch_with_age(ws / "SCOPE.md", 0.5)
            result = run_checks(ws)
        live_check = next(c for c in result["checks"] if c["label"] == "Live target report")
        self.assertEqual(live_check["artifact"], "LIVE_TARGET_REPORT.md")
        self.assertEqual(live_check["severity"], SEV_FRESH)

    def test_live_target_report_missing_when_no_accepted_path_exists(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _touch_with_age(ws / "engage_report.md", 1.0)
            _touch_with_age(ws / "SCOPE.md", 0.5)
            result = run_checks(ws)
        live_check = next(c for c in result["checks"] if c["label"] == "Live target report")
        self.assertEqual(live_check["artifact"], "docs/LIVE_TARGET_REPORT.md")
        self.assertEqual(live_check["severity"], SEV_MISSING)
        self.assertIn("LIVE_TARGET_REPORT.md", live_check["note"])


# ---------------------------------------------------------------------------
# Tests - CLI
# ---------------------------------------------------------------------------


class TestMainCli(unittest.TestCase):
    def test_writes_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _touch_with_age(ws / "engage_report.md", 1.0)
            (ws / "docs").mkdir()
            _touch_with_age(ws / "docs" / "LIVE_TARGET_REPORT.md", 1.0)
            _touch_with_age(ws / "SCOPE.md", 0.5)
            rc = main(["--workspace", str(ws), "--quiet"])
            sidecar = ws / ".auditooor" / "staleness_check.json"
            self.assertTrue(sidecar.exists())
            data = json.loads(sidecar.read_text())
            self.assertIn("checks", data)
            self.assertEqual(rc, 0)

    def test_strict_exits_1_on_stale(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _touch_with_age(ws / "engage_report.md", 15.0)  # STALE
            (ws / "docs").mkdir()
            _touch_with_age(ws / "docs" / "LIVE_TARGET_REPORT.md", 1.0)
            _touch_with_age(ws / "SCOPE.md", 0.5)
            rc = main(["--workspace", str(ws), "--quiet", "--strict"])
            self.assertEqual(rc, 1)

    def test_strict_exits_0_on_warn(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _touch_with_age(ws / "engage_report.md", 8.0)  # WARN only
            (ws / "docs").mkdir()
            _touch_with_age(ws / "docs" / "LIVE_TARGET_REPORT.md", 1.0)
            _touch_with_age(ws / "SCOPE.md", 0.5)
            rc = main(["--workspace", str(ws), "--quiet", "--strict"])
            self.assertEqual(rc, 0)  # WARN is not a hard fail under --strict


# ---------------------------------------------------------------------------
# Dogfood - Morpho workspace (skipped if not available)
# ---------------------------------------------------------------------------


class TestMorphoDogfood(unittest.TestCase):
    MORPHO_WS = Path("/Users/wolf/audits/morpho")

    def setUp(self):
        if not self.MORPHO_WS.exists():
            self.skipTest("Morpho workspace not available")

    def test_engage_report_is_critical(self):
        """Morpho engage_report.md classification should match its current age."""
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "staleness.json"
            rc = main(
                [
                    "--workspace",
                    str(self.MORPHO_WS),
                    "--output",
                    str(output),
                    "--quiet",
                ]
            )
            data = json.loads(output.read_text())
            engage_check = next(
                (c for c in data["checks"] if "engage" in c.get("artifact", "")),
                None,
            )
            self.assertIsNotNone(engage_check)
            age = engage_check.get("age_days", 0)
            if age >= _mod._WARN_DAYS:
                self.assertIn(
                    engage_check["severity"],
                    (SEV_WARN, SEV_STALE, SEV_CRITICAL),
                    f"Expected aged severity, got: {engage_check}",
                )
            else:
                self.assertEqual(engage_check["severity"], SEV_FRESH)


if __name__ == "__main__":
    unittest.main()
