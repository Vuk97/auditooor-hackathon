"""Unit tests for Rule 21 permanent-impact five-ask template preflight."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "permanent-impact-five-ask-template-check.py"
_spec = importlib.util.spec_from_file_location("permanent_impact_five_ask_template_check", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write_case(body: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix="r21_five_ask_"))
    draft = root / "draft.md"
    draft.write_text(body, encoding="utf-8")
    return draft


COMPLETE_FIVE_ASK = """Severity: CRITICAL

## Ask coverage
- Who is affected: all validators and users with pending exits.
- What exact asset/state is frozen: withdrawal queue state is frozen and user funds remain locked.
- Why recovery/admin/governance/restart cannot clear it: restart cannot clear the poisoned queue and governance cannot recover the skipped index without a migration.
- Duration/permanence: the lock persists indefinitely until hardfork or state migration.
- Source/runtime proof: source anchor is x/queue/keeper.go and runtime proof is TestExitQueuePermanentFreeze.

Impact: permanent freezing of funds.
"""


class PermanentImpactFiveAskTemplateTests(unittest.TestCase):
    def test_out_of_scope_temporary_claim_passes(self) -> None:
        draft = _write_case("Severity: HIGH\nTemporary matching engine degradation for a few blocks.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_negative_scope_permanent_keywords_pass(self) -> None:
        draft = _write_case("Severity: CRITICAL\nnot_proven: permanent freezing; no permanent impact is claimed.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_high_permanent_freezing_without_five_asks_fails(self) -> None:
        draft = _write_case("Severity: HIGH\nSelected impact: permanent freezing of user funds.")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-five-ask-coverage")
        self.assertIn("who_affected", payload["evidence"]["missing_asks"])

    def test_critical_complete_five_ask_block_passes(self) -> None:
        draft = _write_case(COMPLETE_FIVE_ASK)
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-five-ask-covered")
        self.assertEqual(payload["evidence"]["missing_asks"], [])

    def test_honest_walkback_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\n"
            "Earlier draft called this permanent freezing, but honest walkback: admin can clear the queue, "
            "so this is not permanent-class impact."
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-honest-walkback")

    def test_below_severity_threshold_passes_by_default(self) -> None:
        draft = _write_case("Severity: MEDIUM\nPermanent freezing of one test account is possible.")
        rc, payload = mod.run(draft, strict=False)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-below-severity-threshold")

    def test_strict_enforces_below_severity_threshold(self) -> None:
        draft = _write_case("Severity: MEDIUM\nPermanent freezing of one test account is possible.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-five-ask-coverage")

    def test_rebuttal_marker_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\n"
            "Permanent freezing is mentioned only because the contest taxonomy uses that label.\n"
            "<!-- r21-rebuttal: source shows all affected balances can be unlocked by permissionless retry -->"
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("permissionless retry", payload["rebuttal"])

    def test_cli_json_output(self) -> None:
        draft = _write_case(COMPLETE_FIVE_ASK)
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--strict", "--json", str(draft)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-five-ask-covered")
        self.assertEqual(payload["gate"], "R21-PERMANENT-IMPACT-5-ASK-TEMPLATE")

    def test_missing_file_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/file.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    # --- Regression: not_proven_impacts negation context (iter9 Lane III FP fix) ---
    def test_not_proven_impacts_field_is_negation_context(self) -> None:
        """not_proven_impacts: ... permanent freezing ... must be treated as negation context."""
        draft = _write_case(
            "Severity: CRITICAL\n"
            "- not_proven_impacts: Direct loss of user funds; permanent freezing of funds;"
            " unauthorized minting; network-level downtime.\n"
            "Actual impact: read-only RPC query panic, no on-chain state change.\n"
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertIn(payload["verdict"], ("pass-out-of-scope", "pass-below-severity-threshold"))

    def test_not_proven_impacts_does_not_suppress_real_trigger(self) -> None:
        """A real permanent freezing claim OUTSIDE the not_proven_impacts line still triggers R21."""
        draft = _write_case(
            "Severity: CRITICAL\n"
            "- not_proven_impacts: loss of funds.\n"
            "This bug causes permanent freezing of funds with no admin recovery path.\n"
        )
        rc, payload = mod.run(draft, strict=False)
        # severity is in scope (CRITICAL) and trigger outside negation context -> must NOT pass-out-of-scope
        self.assertNotEqual(payload["verdict"], "pass-out-of-scope")


if __name__ == "__main__":
    unittest.main(verbosity=2)
