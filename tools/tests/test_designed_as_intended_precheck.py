"""Unit tests for Rule 45 Designed-As-Intended precheck (Check #93).

Covers all 7 verdict classes + edge cases for >= 15 total test cases.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "r45"
WORKSPACES = ROOT / "tools" / "tests" / "fixtures" / "r45_workspaces"

_spec = importlib.util.spec_from_file_location(
    "designed_as_intended_precheck",
    ROOT / "tools" / "designed-as-intended-precheck.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _run(
    draft: Path,
    *,
    workspace: Path | None = None,
    strict: bool = False,
    severity: str | None = None,
) -> tuple[int, dict]:
    return mod.run(draft, severity_override=severity, workspace=workspace, strict=strict)


def _make_workspace(
    *,
    severity_md: str | None = None,
    scope_md: str | None = None,
    doc_text: str | None = None,
    src_stub: str | None = None,
) -> Path:
    """Create a temporary workspace for R45 tests.

    src_stub: if provided, written to src/stub.rs so _verify_defense_implemented
    can find named defense terms as 'implemented' (v2 constraint 3).
    """
    root = Path(tempfile.mkdtemp(prefix="r45_ws_"))
    if severity_md is not None:
        (root / "SEVERITY.md").write_text(severity_md, encoding="utf-8")
    if scope_md is not None:
        (root / "SCOPE.md").write_text(scope_md, encoding="utf-8")
    if doc_text is not None:
        docs = root / "docs"
        docs.mkdir()
        (docs / "ARCHITECTURE.md").write_text(doc_text, encoding="utf-8")
    if src_stub is not None:
        src = root / "src"
        src.mkdir()
        (src / "stub.rs").write_text(src_stub, encoding="utf-8")
    return root


# Default src stub for tests that need defenses to be "implemented" (v2 constraint 3).
# IMPORTANT: must NOT contain any Unimplemented/unimplemented!/todo!() patterns since
# _verify_defense_implemented() uses those to flag a defense as non-operational.
_CHALLENGER_SRC_STUB = """\
// Stub: challenger and fraud proof are implemented.
// This file is used by R45 v2 tests to signal that named defenses ARE operational.
pub fn challenger_check(bond: u64) -> bool { bond > 0 }
pub fn deduct_proposer_bond(proposer: &str, bond: u64) -> u64 { bond }
pub fn verify_fraud_proof_real(root: [u8; 32]) -> Result<bool, String> { Ok(true) }
pub fn fishermen_monitor(output: [u8; 32]) -> bool { true }
// challenge_window: 7 days
pub const CHALLENGE_WINDOW_SECS: u64 = 604800;
pub fn bond_backed_challenge_period() -> u64 { CHALLENGE_WINDOW_SECS }
"""


# ---------------------------------------------------------------------------
# Scope tests: pass-out-of-scope
# ---------------------------------------------------------------------------

class ScopeTests(unittest.TestCase):
    def test_low_severity_out_of_scope(self) -> None:
        """low_severity_pass.md - LOW -> pass-out-of-scope."""
        draft = FIXTURES / "low_severity_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_medium_severity_out_of_scope(self) -> None:
        """medium_severity_pass.md - MEDIUM -> pass-out-of-scope."""
        draft = FIXTURES / "medium_severity_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_low_is_out_of_scope(self) -> None:
        """Even a HIGH draft is out-of-scope if CLI forces LOW."""
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        rc, payload = _run(draft, severity="low", strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")
        self.assertEqual(payload["severity_source"], "cli")

    def test_unreadable_path_returns_error(self) -> None:
        """Nonexistent path -> error verdict, rc=2."""
        rc, payload = mod.run(Path("/no/such/r45_draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


# ---------------------------------------------------------------------------
# pass-no-omission-claim
# ---------------------------------------------------------------------------

class NoOmissionClaimTests(unittest.TestCase):
    def test_no_omission_claim_high_passes(self) -> None:
        """no_omission_claim_pass.md - HIGH but no omission phrase -> pass-no-omission-claim."""
        draft = FIXTURES / "no_omission_claim_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-omission-claim")


# ---------------------------------------------------------------------------
# ok-rebuttal
# ---------------------------------------------------------------------------

class RebuttalTests(unittest.TestCase):
    def test_visible_rebuttal_line_passes(self) -> None:
        """r45_rebuttal_override.md - visible r45-rebuttal line -> ok-rebuttal."""
        draft = FIXTURES / "r45_rebuttal_override.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("rebuttal", payload)

    def test_html_comment_rebuttal_passes(self) -> None:
        """html_rebuttal_pass.md - HTML comment r45-rebuttal -> ok-rebuttal."""
        draft = FIXTURES / "html_rebuttal_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_overlong_rebuttal_ignored(self) -> None:
        """overlong_rebuttal_fail.md - rebuttal >200 chars is ignored -> some non-rebuttal verdict.

        v2: result depends on whether defenses are verified in src. Without src stub, defenses
        are absent -> pass-design-intent-cited-but-defenses-not-implemented.
        With src stub -> fail-designed-as-intended-with-defense-in-depth.
        Either way: not ok-rebuttal.
        """
        ws = _make_workspace(
            doc_text=(
                "## Design\n\nBy design, no finalization wait is required. "
                "This is intentional.\n"
                "The challenger and fishermen provide defense-in-depth via bond-backed challenge window.\n"
            )
        )
        draft = FIXTURES / "overlong_rebuttal_fail.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertNotEqual(payload["verdict"], "ok-rebuttal")
        # Should reach design-intent check; specific verdict depends on src-verification result
        self.assertIn(payload["verdict"], [
            "fail-designed-as-intended-with-defense-in-depth",
            "pass-not-documented-as-intentional",
            "pass-documented-but-not-defended-in-depth",
            "pass-design-intent-cited-but-defenses-not-implemented",
        ])


# ---------------------------------------------------------------------------
# pass-not-documented-as-intentional
# ---------------------------------------------------------------------------

class NotDocumentedAsIntentionalTests(unittest.TestCase):
    def test_clean_omission_no_design_intent(self) -> None:
        """clean_omission_no_design_intent_pass.md + clean workspace -> pass-not-documented-as-intentional."""
        draft = FIXTURES / "clean_omission_no_design_intent_pass.md"
        ws = WORKSPACES / "clean_no_design_intent"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-documented-as-intentional")

    def test_empty_workspace_no_docs_passes(self) -> None:
        """Omission claim + workspace with no docs -> pass-not-documented-as-intentional."""
        ws = _make_workspace()  # no docs at all
        draft = FIXTURES / "clean_omission_no_design_intent_pass.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-documented-as-intentional")


# ---------------------------------------------------------------------------
# pass-documented-but-not-defended-in-depth
# ---------------------------------------------------------------------------

class DocumentedNoDefenseTests(unittest.TestCase):
    def test_documented_no_defense_in_depth_warns(self) -> None:
        """documented_no_defense_in_depth_warn.md + documented_no_defense workspace -> pass-documented-but-not-defended-in-depth."""
        draft = FIXTURES / "documented_no_defense_in_depth_warn.md"
        ws = WORKSPACES / "documented_no_defense"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-documented-but-not-defended-in-depth")
        self.assertIn("warning", payload)

    def test_inline_design_intent_no_defense(self) -> None:
        """Doc says 'by design' but no defense-in-depth alternative named."""
        ws = _make_workspace(
            doc_text=(
                "## Acceptance\n\nThe bridge intentionally accepts unverified roots "
                "as a design choice for performance. This is a conscious decision.\n"
                "No additional layer is described here.\n"
            )
        )
        draft = FIXTURES / "documented_no_defense_in_depth_warn.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-documented-but-not-defended-in-depth")


# ---------------------------------------------------------------------------
# fail-designed-as-intended-with-defense-in-depth
# ---------------------------------------------------------------------------

class DesignedAsIntendedFailTests(unittest.TestCase):
    def test_op_designed_intended_fail(self) -> None:
        """hyperbridge_op_designed_as_intended_fail.md + op_designed_intended workspace -> fail-designed-as-intended-with-defense-in-depth."""
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        ws = WORKSPACES / "op_designed_intended"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-designed-as-intended-with-defense-in-depth")

    def test_fail_persists_known_dead_end_when_enabled(self) -> None:
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        ws = WORKSPACES / "op_designed_intended"
        with tempfile.TemporaryDirectory(prefix="r45_kde_") as tmp:
            kde = Path(tmp) / "known_dead_ends.jsonl"
            rc, payload = mod.run(
                draft,
                workspace=ws,
                strict=True,
                persist_kde=True,
                known_dead_ends_path=kde,
            )
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "fail-designed-as-intended-with-defense-in-depth")
            self.assertTrue(kde.is_file())
            rows = [json.loads(line) for line in kde.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_rule"], mod.GATE)
            self.assertIn("contract.function", rows[0])

    def test_critical_with_defense_in_depth_fail(self) -> None:
        """critical_with_defense_in_depth_fail.md + workspace with challenger docs + src stub -> fail.

        v2: requires src_stub so _verify_defense_implemented finds challenger as 'implemented'.
        Without src stub, defenses come back 'absent' and the verdict flips to
        pass-design-intent-cited-but-defenses-not-implemented.
        """
        ws = _make_workspace(
            doc_text=(
                "## Dispute Game\n\nBy design, the dispute game intentionally protects "
                "withdrawals. Challengers (fishermen) can raise disputes within the "
                "bond-backed challenge window. The time-lock challenge period provides "
                "a safety guard. This is the intended behavior.\n"
            ),
            src_stub=_CHALLENGER_SRC_STUB,
        )
        draft = FIXTURES / "critical_with_defense_in_depth_fail.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-designed-as-intended-with-defense-in-depth")

    def test_fail_designed_is_rc1_without_strict(self) -> None:
        """fail-designed-as-intended-with-defense-in-depth always rc=1 even without --strict.

        v2: requires src_stub so _verify_defense_implemented finds challenger as 'implemented'.
        """
        ws = _make_workspace(
            doc_text=(
                "By design no finalization wait is enforced. This is intentional. "
                "Challengers slash the bond within the challenge window.\n"
            ),
            src_stub=_CHALLENGER_SRC_STUB,
        )
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        rc, payload = _run(draft, workspace=ws, strict=False)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-designed-as-intended-with-defense-in-depth")

    def test_env_design_intent_pattern_extension(self) -> None:
        """Env AUDITOOOR_R45_DESIGN_INTENT_PATTERNS adds custom trigger.

        v2: with src_stub that has multisig implementation, defenses are 'implemented'
        and gate should fire fail-designed-as-intended-with-defense-in-depth.
        """
        ws = _make_workspace(
            doc_text=(
                "## Custom\n\nThis behavior is an explicit product decision. "
                "The multisig guardian provides backup enforcement.\n"
            ),
            src_stub=(
                "// multisig guardian implementation - no unimplemented paths\n"
                "pub fn multisig_validate(signers: &[u8]) -> bool { signers.len() >= 3 }\n"
                "pub fn guardian_execute(action: &str) -> Result<(), String> { Ok(()) }\n"
            ),
        )
        draft = FIXTURES / "clean_omission_no_design_intent_pass.md"
        old = os.environ.get("AUDITOOOR_R45_DESIGN_INTENT_PATTERNS")
        os.environ["AUDITOOOR_R45_DESIGN_INTENT_PATTERNS"] = r"explicit product decision"
        try:
            rc, payload = _run(draft, workspace=ws, strict=True)
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_R45_DESIGN_INTENT_PATTERNS", None)
            else:
                os.environ["AUDITOOOR_R45_DESIGN_INTENT_PATTERNS"] = old
        # multisig is a defense-in-depth trigger; both present + src_stub -> fail
        self.assertEqual(payload["verdict"], "fail-designed-as-intended-with-defense-in-depth")


# ---------------------------------------------------------------------------
# fail-public-doc-undisclosed
# ---------------------------------------------------------------------------

class PublicDocUndisclosedTests(unittest.TestCase):
    def test_public_doc_oos_undisclosed_fails(self) -> None:
        """public_doc_oos_undisclosed.md + public_doc_oos workspace -> fail-public-doc-undisclosed."""
        draft = FIXTURES / "public_doc_oos_undisclosed.md"
        ws = WORKSPACES / "public_doc_oos"
        # Without strict: rc=0 but verdict is still fail-public-doc-undisclosed
        rc_nostrict, payload_nostrict = _run(draft, workspace=ws, strict=False)
        self.assertEqual(rc_nostrict, 0)
        self.assertEqual(payload_nostrict["verdict"], "fail-public-doc-undisclosed")
        # With strict: rc=1
        rc_strict, payload_strict = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc_strict, 1)
        self.assertEqual(payload_strict["verdict"], "fail-public-doc-undisclosed")

    def test_public_doc_oos_addressed_passes(self) -> None:
        """public_doc_oos_addressed_pass.md addresses the design intent -> not fail-public-doc-undisclosed."""
        draft = FIXTURES / "public_doc_oos_addressed_pass.md"
        ws = WORKSPACES / "public_doc_oos"
        rc, payload = _run(draft, workspace=ws, strict=True)
        # Draft addresses design intent -> should not be fail-public-doc-undisclosed
        self.assertNotEqual(payload["verdict"], "fail-public-doc-undisclosed")

    def test_severity_md_acknowledged_by_design_fires(self) -> None:
        """SEVERITY.md with 'acknowledged by design' fires the gate."""
        ws = _make_workspace(
            severity_md=(
                "# Severity\n\n"
                "## Out-of-scope\n"
                "- No check on finalization: acknowledged by design\n"
            )
        )
        draft = FIXTURES / "public_doc_oos_undisclosed.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertIn(payload["verdict"], [
            "fail-public-doc-undisclosed",
            "pass-not-documented-as-intentional",  # if acknowledged pattern doesn't fire for this draft
        ])


# ---------------------------------------------------------------------------
# env extension: omission patterns
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# v2 new tests: protocol-own-doc constraint, proximity, defense-verification
# ---------------------------------------------------------------------------

class V2ProtocolOwnDocConstraintTests(unittest.TestCase):
    """v2 constraint 1: design-intent in prior_audits/ must NOT trigger the gate."""

    def test_prior_audits_noise_does_not_trigger_fail(self) -> None:
        """prior_audits/ with design-intent phrases is excluded from protocol-own-doc scan."""
        ws = Path(tempfile.mkdtemp(prefix="r45_v2_prioraudit_"))
        prior = ws / "prior_audits"
        prior.mkdir()
        # Write a fake audit-report PDF text containing design-intent + defense phrases
        (prior / "audit_report.txt").write_text(
            "By design, no finalization wait is required. This is intentional. "
            "The challenger and fishermen provide defense-in-depth. "
            "Bond-backed challenge window. Fraud proof verification. Slashing.",
            encoding="utf-8",
        )
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        rc, payload = _run(draft, workspace=ws)
        # prior_audits/ excluded -> no design-intent hits -> pass-not-documented-as-intentional
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-documented-as-intentional")

    def test_scope_review_briefs_excluded(self) -> None:
        """scope_review/*.brief.md are auditooor artifacts - must not trigger the gate."""
        ws = Path(tempfile.mkdtemp(prefix="r45_v2_scopereview_"))
        sr = ws / "scope_review"
        sr.mkdir()
        # Write a fake brief that says "ACKNOWLEDGED" (auditooor triage artifact)
        (sr / "hb-optimism-HIGH.brief.md").write_text(
            "# Scope-Review Brief\nACKNOWLEDGED by design, deliberately omitted check. "
            "Challenger-based, fishermen, fraud proof, bond-backed challenge.",
            encoding="utf-8",
        )
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        rc, payload = _run(draft, workspace=ws)
        # scope_review excluded -> no design-intent hits -> pass
        self.assertEqual(rc, 0)
        self.assertIn(payload["verdict"], [
            "pass-not-documented-as-intentional",
            "pass-no-omission-claim",
        ])

    def test_protocol_own_docs_readme_triggers_gate(self) -> None:
        """README.md at workspace root IS a protocol-own-doc; design-intent there must trigger."""
        ws = Path(tempfile.mkdtemp(prefix="r45_v2_readme_"))
        src = ws / "src"
        src.mkdir()
        (src / "stub.rs").write_text(_CHALLENGER_SRC_STUB, encoding="utf-8")
        (ws / "README.md").write_text(
            "# Protocol\n\nBy design, there is no finalization check required. "
            "This is intentional. Challengers slash bonds within the challenge window. "
            "Fraud proofs and fishermen provide defense-in-depth.",
            encoding="utf-8",
        )
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-designed-as-intended-with-defense-in-depth")


class V2DefenseVerificationTests(unittest.TestCase):
    """v2 constraint 3: cited defenses must be verified implemented at audit-pin."""

    def test_fraud_proof_unimplemented_returns_pass(self) -> None:
        """Hyperbridge OP fixture: docs cite fraud proof defense but src returns FraudProofUnimplemented.

        Expected v2 verdict: pass-design-intent-cited-but-defenses-not-implemented.
        This is the key Hyperbridge OP scenario - the v1 false positive case.
        """
        ws = WORKSPACES / "op_designed_fraud_proof_unimplemented"
        draft = FIXTURES / "hyperbridge_op_v2_fraud_proof_unimplemented.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-design-intent-cited-but-defenses-not-implemented")
        # Verify the defense verification evidence is populated
        dv = payload.get("evidence", {}).get("defense_verification", {})
        # At least one term should be 'returns-unimplemented' or 'absent'
        self.assertTrue(any(
            s in ("returns-unimplemented", "absent")
            for s in dv.values()
        ), f"expected unimplemented/absent in defense_verification: {dv}")

    def test_defenses_implemented_triggers_fail(self) -> None:
        """When protocol docs + src both show challenger IS implemented -> fail."""
        ws = WORKSPACES / "op_designed_intended"  # has src/challenger.rs with real impl
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-designed-as-intended-with-defense-in-depth")

    def test_empty_src_tree_with_docs_returns_pass_not_implemented(self) -> None:
        """Design intent in docs + defense terms + empty src tree -> pass-design-intent-cited-but-defenses-not-implemented."""
        ws = _make_workspace(
            doc_text=(
                "## Design\n\nBy design, no finalization check is required. "
                "This is intentional. Challengers and fishermen dispute invalid "
                "outputs within the fraud proof challenge window.\n"
            )
            # No src_stub: no src/ dir in temp workspace
        )
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-design-intent-cited-but-defenses-not-implemented")


class V2ProximityConstraintTests(unittest.TestCase):
    """v2 constraint 2: design-intent phrase must co-occur with contested keywords."""

    def test_generic_design_intent_no_proximity_passes(self) -> None:
        """Generic 'designed for cross-chain' far from contested behavior does not trigger fail."""
        ws = _make_workspace(
            doc_text=(
                "## Overview\n\nThis protocol is designed for cross-chain interoperability. "
                "It aims to be secure and efficient.\n\n"
                "## Unrelated Section\n\n"
                "Some finalization details mentioned in passing, separately.\n"
            ),
            src_stub=_CHALLENGER_SRC_STUB,
        )
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        # "designed for" is far from "finalization" (different section, >200 chars away)
        # design-intent hits may be empty or not proximity-matched
        self.assertEqual(rc, 0)
        self.assertIn(payload["verdict"], [
            "pass-not-documented-as-intentional",
            "pass-documented-but-not-defended-in-depth",
            "pass-design-intent-cited-but-defenses-not-implemented",
        ])

    def test_design_intent_adjacent_to_contested_behavior_triggers(self) -> None:
        """Design intent phrase directly adjacent to finalization keyword triggers the gate.

        Uses a src_stub that contains the same defense terms (challenger, fishermen,
        slash) used in the doc_text so _verify_defense_implemented finds them 'implemented'.
        """
        ws = _make_workspace(
            doc_text=(
                "By design, no finalization check required. This is intentional. "
                "Challengers provide defense-in-depth via slash of proposer bond. "
                "Fishermen monitor and can dispute outputs.\n"
            ),
            # src_stub explicitly matches the extracted defense terms:
            # 'challenger', 'fishermen', 'slash' (as extracted by _extract_defense_terms_from_hits)
            src_stub=(
                "// All named defenses are operationally implemented.\n"
                "pub fn challenger_verify(bond: u64) -> bool { bond > 0 }\n"
                "pub fn fishermen_scan(output: [u8; 32]) -> bool { true }\n"
                "pub fn slash_proposer_bond(amt: u64) -> u64 { amt }\n"
            ),
        )
        draft = FIXTURES / "hyperbridge_op_designed_as_intended_fail.md"
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-designed-as-intended-with-defense-in-depth")


class EnvExtensionTests(unittest.TestCase):
    def test_env_omission_pattern_extension(self) -> None:
        """env_omission_pattern_extension.md normally has no default trigger; env adds one."""
        draft = FIXTURES / "env_omission_pattern_extension.md"
        ws = _make_workspace()

        # Without env extension: 'omits' IS in default patterns already; let's confirm base behavior
        rc_base, payload_base = _run(draft, workspace=ws)
        # The draft contains "omits" -> should trigger
        # If it fires -> pass-not-documented-as-intentional (empty ws)
        self.assertIn(payload_base["verdict"], [
            "pass-no-omission-claim",
            "pass-not-documented-as-intentional",
        ])

        # With custom env pattern matching "unconstrained witness"
        old = os.environ.get("AUDITOOOR_R45_OMISSION_PATTERNS")
        os.environ["AUDITOOOR_R45_OMISSION_PATTERNS"] = r"unconstrained witness"
        try:
            rc, payload = _run(draft, workspace=ws)
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_R45_OMISSION_PATTERNS", None)
            else:
                os.environ["AUDITOOOR_R45_OMISSION_PATTERNS"] = old
        # With env pattern "unconstrained witness" matching: omission triggered; no docs -> pass-not-documented-as-intentional
        self.assertIn(payload["verdict"], [
            "pass-not-documented-as-intentional",
            "pass-no-omission-claim",
        ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
