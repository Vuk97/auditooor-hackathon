"""Tests for tools/severity-calibration-gate.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "severity-calibration-gate.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("severity_calibration_gate", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["severity_calibration_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


mod = _load_module()


def _write_draft(body: str, *, name: str = "draft.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="severity_gate_"))
    path = root / name
    path.write_text(body, encoding="utf-8")
    return path


def _draft(severity: str, body: str) -> str:
    return f"Severity: {severity}\n\n{body}\n"


class SeverityCalibrationGateAxesTests(unittest.TestCase):
    def test_critical_unprivileged_user_fund_theft_passes(self) -> None:
        path = _write_draft(
            _draft(
                "Critical",
                (
                    "An unknown address can drain depositor funds without admin involvement.\n"
                    "The fork test is end-to-end: before and after balances show victim balance decreases "
                    "and attacker balance increases on the production path."
                ),
            )
        )
        rc, row = mod.analyze_file(path)
        self.assertEqual(rc, 0)
        self.assertEqual(row["verdict"], "pass-calibrated")
        self.assertEqual(row["impact_kind"], "user_fund_theft")
        self.assertEqual(row["attacker_path"], "unprivileged")

    def test_critical_protocol_yield_theft_caps_at_high(self) -> None:
        path = _write_draft(
            _draft(
                "Critical",
                (
                    "The attacker steals protocol-accumulated yield and slippage residual.\n"
                    "This is not user funds and no user funds are debited."
                ),
            )
        )
        rc, row = mod.analyze_file(path)
        self.assertEqual(rc, 1)
        self.assertEqual(row["impact_kind"], "protocol_yield_theft")
        self.assertEqual(row["predicted_triager_tier"], "high")
        self.assertIn("critical_claim_maps_to_protocol_yield_theft_not_user_fund_theft", row["blockers"])

    def test_high_griefing_without_fund_impact_caps_at_medium(self) -> None:
        path = _write_draft(
            _draft(
                "High",
                "A user can spam settlement to cause temporary griefing and delayed execution for minutes.",
            )
        )
        rc, row = mod.analyze_file(path)
        self.assertEqual(rc, 1)
        self.assertEqual(row["impact_kind"], "griefing")
        self.assertEqual(row["predicted_triager_tier"], "medium")
        self.assertIn("highplus_claim_maps_to_griefing_without_fund_theft_or_permanent_freeze", row["blockers"])

    def test_permanent_freeze_with_recovery_language_blocks_permanent_claim(self) -> None:
        path = _write_draft(
            _draft(
                "Critical",
                (
                    "The report claims permanent freezing of user funds.\n"
                    "However, admin can recover the funds and a process restart clears the lock."
                ),
            )
        )
        rc, row = mod.analyze_file(path)
        self.assertEqual(rc, 1)
        self.assertEqual(row["recoverability"], "recoverable_or_temporary")
        self.assertIn("permanent_freeze_claim_has_recovery_or_temporary_language", row["blockers"])

    def test_privileged_precondition_caps_highplus_at_medium(self) -> None:
        path = _write_draft(
            _draft(
                "High",
                "The exploit requires governance to first set a trusted role before the attacker can act.",
            )
        )
        rc, row = mod.analyze_file(path)
        self.assertEqual(rc, 1)
        self.assertEqual(row["privileged_precondition"], "present")
        self.assertEqual(row["predicted_triager_tier"], "medium")
        self.assertIn("highplus_claim_requires_privileged_precondition", row["blockers"])

    def test_critical_synthetic_proof_only_blocks_until_hardened(self) -> None:
        path = _write_draft(
            _draft(
                "Critical",
                (
                    "An unknown address can drain user funds.\n"
                    "The proof is a toy harness with mock balances and a unit test only."
                ),
            )
        )
        rc, row = mod.analyze_file(path)
        self.assertEqual(rc, 1)
        self.assertIn("synthetic_or_component_only_proof", row["proof_risks"])
        self.assertIn("critical_claim_has_synthetic_or_component_only_proof", row["blockers"])

    def test_negated_mock_language_does_not_mark_synthetic(self) -> None:
        path = _write_draft(
            _draft(
                "Critical",
                (
                    "Permanent freezing of user funds occurs on the production path.\n"
                    "The proof is an end-to-end integration test through FinalizeBlock.\n"
                    "No mock component, no stub, and no manual state edit is used."
                ),
            )
        )
        rc, row = mod.analyze_file(path)
        self.assertEqual(rc, 0)
        self.assertNotIn("synthetic_or_component_only_proof", row["proof_risks"])
        self.assertNotIn("critical_claim_has_synthetic_or_component_only_proof", row["blockers"])


class SeverityCalibrationGateEnvelopeTests(unittest.TestCase):
    def test_build_envelope_counts_fail_and_pass(self) -> None:
        passing = _write_draft(
            _draft(
                "High",
                (
                    "Temporary freeze of user funds occurs on the production path.\n"
                    "The integration test is end-to-end."
                ),
            ),
            name="passing.md",
        )
        failing = _write_draft(
            _draft("Critical", "Critical claim, but this is theft of unclaimed yield, not user funds."),
            name="failing.md",
        )
        rc, env = mod.build_envelope([passing, failing], generated_at="2026-05-17T00:00:00Z")
        self.assertEqual(rc, 1)
        self.assertEqual(env["schema"], "auditooor.severity_calibration_gate.v1")
        self.assertEqual(env["overall_verdict"], "fail")
        self.assertEqual(env["verdict_counts"]["fail-severity-overclaim"], 1)

    def test_cli_json_and_markdown_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="severity_gate_cli_") as tmp:
            root = Path(tmp)
            draft = root / "draft.md"
            report = root / "report.md"
            draft.write_text(
                _draft("High", "A user can spam settlement to cause temporary griefing for minutes."),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(draft),
                    "--json",
                    "--markdown-report",
                    str(report),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["overall_verdict"], "fail")
            text = report.read_text(encoding="utf-8")
            self.assertIn("Severity Calibration Gate Report", text)
            self.assertIn("griefing", text)


class SeverityCalibrationOutcomeLessonAdoptionTests(unittest.TestCase):
    """HACKERMAN_V3 Lane J5a: low_severity_cap_triggered drives a medium cap."""

    def test_payload_carries_outcome_lesson_gate_field(self) -> None:
        path = _write_draft(
            _draft(
                "High",
                (
                    "An unknown address can drain depositor funds without admin involvement.\n"
                    "The fork test is end-to-end: before and after balances show victim balance decreases."
                ),
            )
        )
        _, row = mod.analyze_file(path)
        self.assertIn("outcome_lesson_gate", row)
        self.assertTrue(row["outcome_lesson_gate"]["available"])

    def test_low_severity_cap_predicate_caps_high_to_medium(self) -> None:
        # Revert #991/#995 low caps: the shared classifier's
        # low_severity_cap_triggered predicate deterministically caps a High
        # claim to medium and adds a blocker.
        path = _write_draft(
            _draft(
                "High",
                (
                    "Impact is dust only with no material loss; severity is capped at low.\n"
                    "The finding should be downgraded to informational."
                ),
            )
        )
        rc, row = mod.analyze_file(path)
        self.assertEqual(rc, 1)
        self.assertTrue(row["outcome_lesson_gate"]["low_cap_triggered"])
        self.assertIn("outcome_lesson_low_severity_cap_triggered", row["blockers"])
        self.assertEqual(row["predicted_triager_tier"], "medium")
        self.assertEqual(row["verdict"], "fail-severity-overclaim")

    def test_low_severity_cap_rebuttal_clears_blocker(self) -> None:
        path = _write_draft(
            _draft(
                "High",
                (
                    "Impact is dust only with no material loss; severity is capped at low.\n"
                    "The finding should be downgraded to informational.\n"
                    "<!-- severity-calibration-gate-rebuttal: low-cap text is a quoted "
                    "triager objection, not this draft's claim -->"
                ),
            )
        )
        rc, row = mod.analyze_file(path)
        self.assertEqual(rc, 0)
        self.assertEqual(row["blockers"], [])


if __name__ == "__main__":
    unittest.main()
