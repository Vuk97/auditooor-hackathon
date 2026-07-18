#!/usr/bin/env python3
"""Tests for the lightweight submission-gate watchdog."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "pre-submit-watchdog.py"
_spec = importlib.util.spec_from_file_location("pre_submit_watchdog", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="watchdog_ws_"))
    ws = root / "audit"
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / "poc-tests" / "case").mkdir(parents=True)
    return ws


PASSING_DRAFT = """# Temporary accounting bug allows bounded user griefing

Severity: Medium

## Impact

The bug causes a bounded accounting mismatch in a test path.

## Impact Contract

- Victim: protocol users
- Source proof: src/vault.rs:10-30
- Harness scaffold: poc-tests/case/poc_test.rs
- selected_impact: Griefing
- severity_tier: Medium
- listed_impact_proven: true
- evidence_class: source_review
- oos_traps: none. No privileged path is used.
- stop_condition: stop if the source proof no longer reaches the affected state.
"""


FAILING_DRAFT = """# Missing guard bug allows direct loss of user funds

Severity: High

## Impact

The attacker causes loss of funds.
"""


class PreSubmitWatchdogTests(unittest.TestCase):
    def test_quick_mode_writes_passing_sidecar(self) -> None:
        ws = _workspace()
        draft = ws / "submissions" / "staging" / "candidate-MEDIUM.md"
        draft.write_text(PASSING_DRAFT, encoding="utf-8")
        summary = mod.run_once(ws, mode="quick", changed=[draft], out_dir=None)
        self.assertEqual(summary["status"], "pass", json.dumps(summary, indent=2))
        self.assertEqual(summary["draft_count"], 1)
        status_path = Path(summary["statuses"][0]["status_path"])
        payload = json.loads(status_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["mode"], "quick")
        self.assertTrue(any(gate["gate"] == "L27-IMPACT-CONTRACT" for gate in payload["gates"]))

    def test_quick_mode_records_failing_gate(self) -> None:
        ws = _workspace()
        draft = ws / "submissions" / "staging" / "candidate-HIGH.md"
        draft.write_text(FAILING_DRAFT, encoding="utf-8")
        summary = mod.run_once(ws, mode="quick", changed=[draft], out_dir=None)
        self.assertEqual(summary["status"], "fail")
        status_path = Path(summary["statuses"][0]["status_path"])
        payload = json.loads(status_path.read_text(encoding="utf-8"))
        failed_gates = {failure["gate"] for failure in payload["failures"]}
        self.assertIn("L27-IMPACT-CONTRACT", failed_gates)

    def test_discover_drafts_scans_submission_dirs(self) -> None:
        ws = _workspace()
        (ws / "submissions" / "staging" / "a.md").write_text(PASSING_DRAFT, encoding="utf-8")
        (ws / "submissions" / "paste_ready").mkdir(exist_ok=True)
        (ws / "submissions" / "paste_ready" / "b.md").write_text(PASSING_DRAFT, encoding="utf-8")
        drafts = {path.name for path in mod.discover_drafts(ws)}
        self.assertEqual(drafts, {"a.md", "b.md"})

    def test_cli_advisory_exits_zero_on_failure(self) -> None:
        ws = _workspace()
        draft = ws / "submissions" / "staging" / "candidate-HIGH.md"
        draft.write_text(FAILING_DRAFT, encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                str(ws),
                "--changed",
                str(draft),
                "--json",
                "--advisory",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["failed_count"], 1)

    def test_cli_non_advisory_exits_nonzero_on_failure(self) -> None:
        ws = _workspace()
        draft = ws / "submissions" / "staging" / "candidate-HIGH.md"
        draft.write_text(FAILING_DRAFT, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(ws), "--changed", str(draft), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "fail")


if __name__ == "__main__":
    unittest.main(verbosity=2)
