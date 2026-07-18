"""Regression tests for P0-1 'tooling-failure-with-counterexample' edge case.

Scenario: a Recon/Chimera run dumps a counterexample artifact file
(counterexample.txt or counterexample.json) into the same directory as the
fuzz log, but the log also contains a tooling-failure shape (e.g. 'No
contracts to fuzz', thread panic, etc.).

Expected behaviour introduced by Wave K-2:
  - tooling-failure log + NO counterexample artifact  → suppressed (status=skipped_tooling_failure)
  - tooling-failure log + counterexample artifact     → tooling_failure_origin (advisory, rc=0)
  - clean log + counterexample artifact               → verified_counterexample (status=recorded)
  - no log content + no artifact                      → no-op (status=error, no records)
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "recon-log-bridge.py"


def _stdlib_only_env() -> dict[str, str]:
    env = os.environ.copy()
    env["AUDITOOOR_DISABLE_NATIVE_RECON_PARSER"] = "1"
    return env


def _run_bridge(ws: Path, log_content: str, log_name: str = "fuzz.log", extra_args: list[str] | None = None) -> tuple[int, dict]:
    """Write log, run bridge, return (returncode, manifest_dict)."""
    log = ws / ".audit_logs" / log_name
    log.parent.mkdir(exist_ok=True)
    log.write_text(log_content)
    cmd = [
        "python3", str(TOOL),
        "--workspace", str(ws),
        "--engine", "medusa",
        "--log", str(log),
        "--print-json",
    ] + (extra_args or [])
    result = subprocess.run(cmd, text=True, capture_output=True, env=_stdlib_only_env())
    manifest: dict = {}
    if result.stdout.strip():
        try:
            manifest = json.loads(result.stdout)
        except ValueError:
            pass
    return result.returncode, manifest


class ToolingFailureOriginTests(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. Tooling-failure log + NO counterexample artifact → suppressed
    # ------------------------------------------------------------------
    def test_tooling_failure_no_artifact_is_suppressed(self) -> None:
        """Existing behaviour preserved: tooling-failure log alone → suppressed."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            rc, manifest = _run_bridge(
                ws,
                "echidna: No contracts found in given file\n",
            )
            self.assertEqual(rc, 0)
            self.assertEqual(manifest["status"], "skipped_tooling_failure")
            self.assertEqual(manifest["truth_label"], "no_targets")
            self.assertFalse(manifest["engine_executed"])
            self.assertFalse(manifest["targets_discovered"])
            self.assertEqual(manifest["pattern_name"], "no_contracts")
            self.assertNotEqual(manifest.get("status"), "tooling_failure_origin")
            self.assertEqual(len(manifest.get("records", [])), 0)

    # ------------------------------------------------------------------
    # 2. Tooling-failure log + counterexample artifact → tooling_failure_origin
    # ------------------------------------------------------------------
    def test_tooling_failure_with_artifact_is_tooling_failure_origin(self) -> None:
        """NEW: tooling-failure log + counterexample.txt artifact → tooling_failure_origin."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            log_dir = ws / ".audit_logs"
            log_dir.mkdir()
            # Write a counterexample.txt artifact alongside the log
            (log_dir / "counterexample.txt").write_text(
                "property_vault_never_drains\nVault.withdraw(200)\n"
            )
            rc, manifest = _run_bridge(
                ws,
                "echidna: No contracts found in given file\n",
            )
            self.assertEqual(rc, 0, msg=f"bridge should not error; stderr: {manifest}")
            self.assertEqual(
                manifest["status"],
                "tooling_failure_origin",
                msg=(
                    f"Expected tooling_failure_origin but got {manifest.get('status')!r}. "
                    "The bridge must detect that a counterexample artifact exists alongside "
                    "a tooling-failure log and classify the run as advisory rather than "
                    "silently suppressed or fully recorded."
                ),
            )
            self.assertEqual(manifest["truth_label"], "no_targets")
            self.assertFalse(manifest["engine_executed"])
            self.assertFalse(manifest["targets_discovered"])
            self.assertEqual(manifest["pattern_name"], "no_contracts")
            # Must NOT produce a verified counterexample record
            self.assertEqual(
                len(manifest.get("records", [])), 0,
                msg="tooling_failure_origin must not emit verified counterexample records",
            )
            # Must carry a tooling_failure_origin advisory
            advisories = manifest.get("skipped_advisories", [])
            advisory_types = [a.get("advisory_type") for a in advisories]
            self.assertIn(
                "recon_log_bridge_tooling_failure_origin",
                advisory_types,
                msg="tooling_failure_origin advisory entry must be present in skipped_advisories",
            )
            # Advisory must name the artifact that was found
            origin_advisory = next(
                a for a in advisories if a.get("advisory_type") == "recon_log_bridge_tooling_failure_origin"
            )
            self.assertIn(
                "counterexample_artifact",
                origin_advisory,
                msg="tooling_failure_origin advisory must record the artifact path",
            )

    def test_tooling_failure_with_json_artifact_is_tooling_failure_origin(self) -> None:
        """NEW: counterexample.json alongside tooling-failure log → tooling_failure_origin."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            log_dir = ws / ".audit_logs"
            log_dir.mkdir()
            (log_dir / "counterexample.json").write_text(
                json.dumps({"property": "invariant_noBadDebt", "calls": ["Market.resolve(1)"]})
            )
            rc, manifest = _run_bridge(
                ws,
                "thread 'main' panicked at 'called `Option::unwrap()` on a `None` value'\n",
            )
            self.assertEqual(rc, 0)
            self.assertEqual(manifest["status"], "tooling_failure_origin")
            self.assertEqual(manifest["truth_label"], "tooling_failure")
            self.assertFalse(manifest["engine_executed"])
            self.assertIsNone(manifest["targets_discovered"])
            self.assertEqual(manifest["pattern_name"], "panic")
            advisories = manifest.get("skipped_advisories", [])
            self.assertTrue(
                any(a.get("advisory_type") == "recon_log_bridge_tooling_failure_origin" for a in advisories)
            )

    # ------------------------------------------------------------------
    # 3. Clean log + counterexample artifact → verified_counterexample (status=recorded)
    # ------------------------------------------------------------------
    def test_clean_log_with_artifact_is_still_recorded(self) -> None:
        """Existing behaviour preserved: a clean failure log records normally regardless of artifact."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            log_dir = ws / ".audit_logs"
            log_dir.mkdir()
            # Put a counterexample artifact in the log dir
            (log_dir / "counterexample.txt").write_text(
                "property_vault_never_drains\nVault.withdraw(200)\n"
            )
            rc, manifest = _run_bridge(
                ws,
                "FAILED property_vault_never_drains\nCall sequence:\n  Vault.withdraw(200)\n",
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                manifest["status"],
                "recorded",
                msg="Clean failure log must still produce status=recorded (not affected by artifact)",
            )
            self.assertEqual(manifest["truth_label"], "counterexample")
            self.assertTrue(manifest["engine_executed"])
            self.assertTrue(manifest["targets_discovered"])
            self.assertEqual(len(manifest.get("records", [])), 1)
            self.assertNotIn(
                "tooling_failure_origin",
                manifest.get("status", ""),
                msg="Clean log must not be misclassified as tooling_failure_origin",
            )

    # ------------------------------------------------------------------
    # 4. No log content + no artifact → no-op (status=error, no records)
    # ------------------------------------------------------------------
    def test_empty_log_no_artifact_is_noop(self) -> None:
        """Empty log with no artifact → status=error (no records, no advisory)."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            rc, manifest = _run_bridge(ws, "")
            self.assertEqual(rc, 0)
            self.assertEqual(manifest["status"], "error")
            self.assertEqual(manifest["truth_label"], "parser_failure")
            self.assertIsNone(manifest["engine_executed"])
            self.assertIsNone(manifest["targets_discovered"])
            self.assertEqual(len(manifest.get("records", [])), 0)
            # Must NOT be classified as tooling_failure_origin (no pattern matched)
            self.assertNotEqual(manifest.get("status"), "tooling_failure_origin")


if __name__ == "__main__":
    unittest.main()
