"""Unit tests for draft-level severity calibration preflight."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "severity-calibration-check.py"
_spec = importlib.util.spec_from_file_location("severity_calibration_check", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write_case(body: str, *, filename: str = "draft-CRITICAL.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="severity_calibration_"))
    draft = root / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _draft(*, severity: str = "Critical", body: str = "") -> str:
    return f"Severity: {severity}\n\n{body}\n"


class SeverityCalibrationScopeTests(unittest.TestCase):
    def test_medium_severity_is_out_of_scope(self) -> None:
        draft = _write_case(_draft(severity="Medium", body="Protocol yield can be stolen."))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_triggers_gate(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="The residual is unclaimed yield, not user funds.",
            ),
            filename="draft.md",
        )
        rc, payload = mod.run(draft, severity_override="Critical", strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["claimed_severity"], "critical")
        self.assertIn("critical_claim_maps_to_unclaimed_yield_not_direct_user_funds", payload["overclaim_reasons"])


class SeverityCalibrationHardFailTests(unittest.TestCase):
    def test_critical_unclaimed_yield_maps_to_high(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "Selected impact: direct theft.\n"
                    "The residual is protocol-accumulated unclaimed yield and slippage residual."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-severity-overclaim")
        self.assertEqual(payload["predicted_triager_tier"], "high")

    def test_critical_internal_accounting_maps_to_medium(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "Selected impact: direct theft.\n"
                    "The issue is protocol-owned module account accounting drift; no user subaccount is debited."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["predicted_triager_tier"], "medium")
        self.assertIn("critical_claim_appears_protocol_internal_or_reconcilable", payload["overclaim_reasons"])

    def test_critical_privileged_precondition_maps_to_medium(self) -> None:
        draft = _write_case(
            _draft(
                body="The exploit requires governance to first switch the vault into privileged operator mode."
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["predicted_triager_tier"], "medium")
        self.assertIn("critical_claim_requires_privileged_or_operator_action", payload["overclaim_reasons"])

    def test_permanent_claim_restart_heals_fails(self) -> None:
        draft = _write_case(
            _draft(
                severity="High",
                body="Selected impact: permanent freezing. A process restart clears the staleness.",
            ),
            filename="draft-HIGH.md",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertIn("permanent_impact_claim_contradicted_by_restart_heals_disclosure", payload["overclaim_reasons"])


class SeverityCalibrationPositiveTests(unittest.TestCase):
    def test_critical_user_funds_unprivileged_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "Unknown address can cause direct theft of user funds without privileged accounts.\n"
                    "The PoC debits victim depositor funds end-to-end."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-calibrated")
        self.assertEqual(payload["predicted_triager_tier"], "critical")

    def test_network_claim_without_multivalidator_is_advisory(self) -> None:
        draft = _write_case(
            _draft(
                severity="High",
                body="Network-level liveness failure in FinalizeBlock.",
            ),
            filename="draft-HIGH.md",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-with-advisory")
        self.assertIn("network_liveness_claim_missing_multi_validator_evidence", payload["advisory_reasons"])

    def test_rebuttal_marker_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "<!-- severity-calibration-rebuttal: privileged setup is only harness initialization; "
                    "attacker path is unvetted. -->\n"
                    "The setup mentions admin but attack is unprivileged."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")


class SeverityCalibrationCliTests(unittest.TestCase):
    def test_cli_emits_json_and_nonzero_for_violation(self) -> None:
        draft = _write_case(_draft(body="Critical claim, but this is theft of unclaimed yield."))
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--strict", "--json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], "auditooor.severity_calibration_check.v1")
        self.assertEqual(payload["verdict"], "fail-severity-overclaim")


if __name__ == "__main__":
    unittest.main()
