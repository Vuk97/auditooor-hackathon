#!/usr/bin/env python3
"""Regression coverage for record-triage without PyYAML installed."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "record-triage.sh"
LEDGER = ROOT / "detectors" / "_hits_ledger.yaml"


class RecordTriageYamlOptionalTests(unittest.TestCase):
    def test_missing_pyyaml_records_unknown_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            backup = tmp_root / "_hits_ledger.yaml"
            shutil.copy2(LEDGER, backup)
            shadow = tmp_root / "shadow"
            shadow.mkdir()
            (shadow / "yaml.py").write_text(
                "raise ModuleNotFoundError(\"No module named 'yaml'\")\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(shadow)
            try:
                proc = subprocess.run(
                    [
                        "bash",
                        str(TOOL),
                        "unit-test-detector",
                        "unit-ws",
                        "unit-finding",
                        "UNKNOWN",
                    ],
                    cwd=ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                combined = proc.stdout + proc.stderr
                self.assertEqual(proc.returncode, 0, combined)
                self.assertIn("recorded: unit-test-detector", combined)
                self.assertNotIn("Traceback", combined)
                self.assertNotIn("No module named 'yaml'", combined)
                self.assertIn("unit-test-detector:", LEDGER.read_text())
                try:
                    import yaml  # type: ignore
                except ImportError:
                    yaml = None
                if yaml is not None:
                    parsed = yaml.safe_load(LEDGER.read_text())
                    self.assertIn("unit-test-detector", parsed["detectors"])
            finally:
                shutil.copy2(backup, LEDGER)


if __name__ == "__main__":
    unittest.main()
