"""Unit tests for Rule 23 comparative-baseline preflight."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "comparative-baseline-check.py"
_spec = importlib.util.spec_from_file_location("comparative_baseline_check", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write_case(body: str, *, filename: str = "draft-HIGH.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="r23_comparative_"))
    draft = root / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _draft(*, severity: str = "High", body: str = "") -> str:
    return f"Severity: {severity}\n\n{body}\n"


class ComparativeBaselineScopeTests(unittest.TestCase):
    def test_medium_severity_is_out_of_scope(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="The target is 40% slower than upstream under the same workload.",
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_high_without_comparative_trigger_is_out_of_scope(self) -> None:
        draft = _write_case(_draft(body="The bug lets an unauthorized caller pause the vault."))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_triggers_gate(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="The cap was loosened versus upstream and causes 3x latency.",
            ),
            filename="draft.md",
        )
        rc, payload = mod.run(draft, severity_override="High", strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["severity_source"], "cli")
        self.assertEqual(payload["verdict"], "fail-comparative-baseline-incomplete")


class ComparativeBaselinePositiveTests(unittest.TestCase):
    def test_complete_same_workload_baseline_passes(self) -> None:
        draft = _write_case(
            _draft(
                severity="Critical",
                body=(
                    "Regression claim: the fork loosened the nested-message cap versus upstream.\n"
                    "Comparator: upstream cap=100 vs target cap=1000 on the same-workload fixture.\n"
                    "Measurement method: go test ./protocol/x/clob/... -run TestNestedCap "
                    "-count=5 with seed 1337 and identical 1MB tx corpus.\n"
                    "Pass/fail threshold: fail if p95 DeliverTx latency exceeds 200ms or "
                    "target/upstream ratio is >= 2x; observed 280ms vs 12ms."
                ),
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-comparative-baseline-complete")
        self.assertFalse(payload["missing"])

    def test_rebuttal_marker_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "<!-- r23-rebuttal: comparative terms quote triager rubric; "
                    "the filed impact is non-comparative authorization bypass. -->\n"
                    "The text mentions upstream only to explain provenance."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("comparative terms", payload["rebuttal"])


class ComparativeBaselineNegativeTests(unittest.TestCase):
    def test_high_comparative_claim_missing_method_and_threshold_fails(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "The parameter cap was loosened from 100 to 1000 versus upstream, "
                    "causing bounded matching-engine degradation."
                )
            )
        )
        rc, payload = mod.run(draft, strict=False)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-comparative-baseline-incomplete")
        self.assertIn("measurement_method", payload["missing"])
        self.assertIn("pass_fail_threshold", payload["missing"])

    def test_regression_claim_without_comparator_fails(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "This is a regression that makes settlement 35% slower.\n"
                    "Method: replayed the same fixture with go test -run TestSettlement -count=3.\n"
                    "Threshold: fail if p99 latency exceeds 500ms."
                )
            )
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["missing"], ["concrete_comparator"])

    def test_unreadable_path_returns_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


class ComparativeBaselineCliTests(unittest.TestCase):
    def test_cli_emits_json_and_nonzero_for_violation(self) -> None:
        draft = _write_case(_draft(body="The fork is 3x slower than upstream."))
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--strict", "--json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], "auditooor.comparative_baseline_check.v1")
        self.assertEqual(payload["verdict"], "fail-comparative-baseline-incomplete")
        self.assertTrue(payload["strict"])


if __name__ == "__main__":
    unittest.main()
