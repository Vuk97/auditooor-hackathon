"""Unit tests for Rule 34 control-test discipline preflight."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "control-test-discipline-check.py"
_spec = importlib.util.spec_from_file_location("control_test_discipline_check", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write_case(body: str, *, filename: str = "draft-HIGH.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="r34_control_"))
    draft = root / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _draft(*, severity: str = "High", body: str = "") -> str:
    return f"Severity: {severity}\n\n{body}\n"


class ControlTestDisciplineScopeTests(unittest.TestCase):
    def test_medium_severity_is_out_of_scope(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="Root cause is a missing guard in the settlement path.",
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_high_without_mechanism_trigger_is_out_of_scope(self) -> None:
        draft = _write_case(_draft(body="The attacker can withdraw unclaimed yield."))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_triggers_gate(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="Root cause is zero-share residual capture.",
            ),
            filename="draft.md",
        )
        rc, payload = mod.run(draft, severity_override="High", strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["severity_source"], "cli")
        self.assertEqual(payload["verdict"], "fail-missing-control-test")


class ControlTestDisciplinePositiveTests(unittest.TestCase):
    def test_negative_control_in_draft_passes(self) -> None:
        draft = _write_case(
            _draft(
                severity="Critical",
                body=(
                    "Root cause: the zero-share branch captures residual equity.\n"
                    "Control test: when totalShares remains nonzero, the same workload does not trigger the bug.\n"
                    "The positive case fires only after totalShares=0 with positive residual."
                ),
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-control-or-rebuttal-present")
        self.assertTrue(payload["evidence"]["control_hits"])

    def test_alternative_cause_section_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "The cache ordering panic is the root cause.\n\n"
                    "## Alternative Cause Rebuttal\n"
                    "This is not a teardown panic; the goroutine dump is stable before cleanup."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-control-or-rebuttal-present")
        self.assertTrue(payload["evidence"]["alternative_rebuttal_section_hits"])

    def test_why_this_is_not_specific_alternative_section_passes(self) -> None:
        draft = _write_case(
            "Severity: **High**\n\n"
            "Root cause: zero-share residual capture in the mint branch.\n\n"
            "## Why This Is Not Withdrawal Slippage\n"
            "The same withdrawal path and amount do not fire when shares remain nonzero.\n"
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["severity"], "high")
        self.assertEqual(payload["verdict"], "pass-control-or-rebuttal-present")
        self.assertTrue(payload["evidence"]["alternative_rebuttal_section_hits"])

    def test_control_test_in_poc_file_passes(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="r34_control_poc_"))
        ws = root / "audits" / "demo"
        poc = ws / "poc-tests" / "case"
        poc.mkdir(parents=True)
        (poc / "control_test.go").write_text(
            "func TestZeroShareDoesNotFireWhenSharesRemain(t *testing.T) {}\n",
            encoding="utf-8",
        )
        draft = ws / "submissions" / "draft-HIGH.md"
        draft.parent.mkdir(parents=True)
        draft.write_text(
            _draft(
                body=(
                    "<!-- poc-dir: poc-tests/case -->\n"
                    "Root cause: zero-share residual extraction after close-only settlement."
                )
            ),
            encoding="utf-8",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-control-or-rebuttal-present")
        self.assertTrue(payload["evidence"]["control_hits"])
        self.assertTrue(payload["evidence"]["scanned_files"])

    def test_rebuttal_marker_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "<!-- r34-rebuttal: external invariant proof enumerates all adjacent branches; "
                    "a runtime negative control is not meaningful. -->\n"
                    "Root cause is a missing guard in the accounting branch."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")


class ControlTestDisciplineNegativeTests(unittest.TestCase):
    def test_high_mechanism_claim_without_control_fails(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "Root cause: zero-share residual capture in the mint branch.\n"
                    "The PoC proves the positive exploit case."
                )
            )
        )
        rc, payload = mod.run(draft, strict=False)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-control-test")
        self.assertTrue(payload["evidence"]["trigger_hits"])

    def test_unreadable_path_returns_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


class ControlTestDisciplineCliTests(unittest.TestCase):
    def test_cli_emits_json_and_nonzero_for_violation(self) -> None:
        draft = _write_case(_draft(body="Root cause: missing guard in zero-share branch."))
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--strict", "--json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], "auditooor.control_test_discipline_check.v1")
        self.assertEqual(payload["verdict"], "fail-missing-control-test")
        self.assertTrue(payload["strict"])


if __name__ == "__main__":
    unittest.main()
