#!/usr/bin/env python3
"""Regression coverage for AUDITOOOR_CANONICAL_STRICT fail-closed behavior."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
ENGAGE = ROOT / "tools" / "engage.py"
PROGRESS = ROOT / "tools" / "audit-progress.py"
DISPATCH = ROOT / "tools" / "audit-dispatch.py"


def _load(path: Path, name: str):
    tools_dir = str(ROOT / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class CanonicalStrictModeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engage = _load(ENGAGE, "engage_canonical_strict_test")
        cls.progress = _load(PROGRESS, "audit_progress_canonical_strict_test")
        cls.dispatch = _load(DISPATCH, "audit_dispatch_canonical_strict_test")

    def test_progress_forces_fail_fast_despite_legacy_override(self) -> None:
        with patch.dict(os.environ, {
            "AUDITOOOR_CANONICAL_STRICT": "1",
            "AUDITOOOR_AUDIT_NO_FAIL_FAST": "1",
            "CAMPAIGN_SOURCE_MINE": "1",
        }, clear=True):
            cmd = self.progress._build_engage_cmd(Path("/tmp/ws"), False, [])
        self.assertIn("--fail-fast", cmd)

    def test_dispatch_rejects_no_fail_fast_override(self) -> None:
        with patch.dict(os.environ, {
            "AUDITOOOR_CANONICAL_STRICT": "1",
            "AUDITOOOR_AUDIT_NO_FAIL_FAST": "1",
        }, clear=True), patch.object(sys, "argv", ["audit-dispatch.py", "--workspace", "/tmp/ws"]):
            self.assertEqual(self.dispatch.main(), 2)

    def test_engage_rejects_no_fail_fast_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            "AUDITOOOR_CANONICAL_STRICT": "1",
            "AUDITOOOR_AUDIT_NO_FAIL_FAST": "1",
        }, clear=True), patch.object(sys, "argv", ["engage.py", "--workspace", tmp, "--dry-run"]):
            self.assertEqual(self.engage.main(), 2)

    def test_malformed_detector_json_is_rejected_only_in_canonical_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "regex_detectors_manifest.json"
            path.write_text("{not-json", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(self.engage.parse_regex_manifest(path), [])
            with patch.dict(os.environ, {"AUDITOOOR_CANONICAL_STRICT": "1"}, clear=True):
                with self.assertRaises(self.engage.CanonicalStrictJsonError):
                    self.engage.parse_regex_manifest(path)

    def test_malformed_intake_json_is_rejected_only_in_canonical_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "INTAKE_BASELINE.json").write_text("[]", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(self.engage._load_intake_baseline(workspace), {})
            with patch.dict(os.environ, {"AUDITOOOR_CANONICAL_STRICT": "1"}, clear=True):
                with self.assertRaises(self.engage.CanonicalStrictJsonError):
                    self.engage._load_intake_baseline(workspace)

    def test_recorded_subprocess_warning_fails_under_canonical_strict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            "AUDITOOOR_CANONICAL_STRICT": "1",
        }, clear=True), patch.object(
            self.engage, "stage_scan_go", return_value="SUCCESS_WARN rc=7"
        ), patch.object(sys, "argv", [
            "engage.py", "--workspace", tmp, "--stage", "scan-go", "--no-cost-telemetry",
        ]):
            self.assertEqual(self.engage.main(), 1)


if __name__ == "__main__":
    unittest.main()
