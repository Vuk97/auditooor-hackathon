"""test_hunt_residual_llm_depth.py - FIX 1 wiring test.

Verifies the `hunt-residual-llm-depth` Makefile target:
  - exists and is a .PHONY target,
  - skips gracefully when no residual queue is present,
  - when a residual queue with residual_surface_units>0 exists AND no consent
    flag is set, writes the typed hunt_provider_obligation.json (consent-required)
    instead of calling any provider.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent  # auditooor-mcp repo root
MAKEFILE = ROOT / "Makefile"


class TestHuntResidualLLMDepth(unittest.TestCase):
    def test_target_declared(self):
        text = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("hunt-residual-llm-depth:", text)
        self.assertIn(".PHONY: hunt-residual-llm-depth", text)
        # wired into audit-deep before hunt-sidecar-bridge
        self.assertIn(
            'make --no-print-directory hunt-residual-llm-depth WS="$(_WS_RESOLVED)"',
            text,
        )

    def test_batch_generation_is_bounded_and_strict_is_propagated(self):
        text = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("AUDITOOOR_MIMO_BATCH_TIMEOUT", text)
        self.assertIn("_batch_to python3 tools/mimo-harness-batch-gen.py", text)
        self.assertIn("STRICT=1: refusing to continue after incomplete residual-hunt obligations", text)
        self.assertIn(
            'hunt-residual-llm-depth WS="$(_WS_RESOLVED)" $(if $(LIVE),LIVE=1) $(if $(STRICT),STRICT=1)',
            text,
        )

    def test_no_queue_skips(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / "README.md").write_text("test workspace\n", encoding="utf-8")
            proc = subprocess.run(
                ["make", "--no-print-directory", "hunt-residual-llm-depth", f"WS={ws}"],
                cwd=str(ROOT), capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("no residual queue", proc.stdout)

    def test_residual_without_consent_writes_obligation(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ad = ws / ".auditooor"
            ad.mkdir(parents=True)
            (ws / "README.md").write_text("test workspace\n", encoding="utf-8")
            (ad / "coverage_residual_worker_queue.json").write_text(
                json.dumps({
                    "schema": "auditooor.coverage_residual_worker_queue.v1",
                    "residual_surface_units": 3,
                    "items": [],
                }),
                encoding="utf-8",
            )
            env = dict(os.environ)
            env.pop("AUDITOOOR_LLM_HUNT", None)
            env.pop("LIVE", None)
            proc = subprocess.run(
                ["make", "--no-print-directory", "hunt-residual-llm-depth", f"WS={ws}"],
                cwd=str(ROOT), capture_output=True, text=True, timeout=120, env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            obl = ad / "hunt_provider_obligation.json"
            self.assertTrue(obl.is_file(), "obligation not written")
            data = json.loads(obl.read_text(encoding="utf-8"))
            self.assertEqual(data.get("hunt_provider"), "residual-llm-depth")
            self.assertEqual(data.get("status"), "consent-required")
            self.assertEqual(data.get("residual_surface_units"), 3)


if __name__ == "__main__":
    unittest.main()
