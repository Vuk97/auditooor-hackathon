#!/usr/bin/env python3
"""Regression coverage for loop-gate when PyYAML is unavailable."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LOOP_GATE = ROOT / "tools" / "loop-gate.sh"


class LoopGateYamlOptionalTests(unittest.TestCase):
    def test_missing_pyyaml_is_soft_warning_not_import_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ws = base / "ws"
            ws.mkdir()
            (ws / ".auditooor-state.yaml").write_text(
                "\n".join(
                    [
                        "workspace: ws",
                        "initialized_at: 2026-04-24T00:00:00Z",
                        "open_submissions: []",
                        "closed_submissions: []",
                        "last_ledger_sync: never",
                        "last_classifier_retrain: never",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (ws / "concolic").mkdir()
            (ws / "concolic" / "SUMMARY.md").write_text("# ok\n", encoding="utf-8")
            (ws / "economic_hypotheses.md").write_text("# ok\n", encoding="utf-8")
            (ws / "scan-full.log").write_text("ok\n", encoding="utf-8")

            shadow = base / "shadow"
            shadow.mkdir()
            (shadow / "yaml.py").write_text(
                "raise ModuleNotFoundError(\"No module named 'yaml'\")\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(shadow)

            proc = subprocess.run(
                ["bash", str(LOOP_GATE), str(ws)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )

            combined = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 2, combined)
            self.assertIn("PyYAML unavailable", combined)
            self.assertNotIn("Traceback", combined)
            self.assertNotIn("No module named 'yaml'", combined)


if __name__ == "__main__":
    unittest.main()
