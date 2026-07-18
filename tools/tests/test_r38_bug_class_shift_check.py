"""Unit tests for Rule 38 bug-class-shift preflight (Check #73).

Source: docs/WAVE2_W29_NEW_GATES_SPEC_2026-05-16.md §5.1.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "bug_class_shift_check",
    ROOT / "tools" / "bug-class-shift-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r38_shift_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    return root


def _write_draft(body: str, *, filename: str = "draft-HIGH.md", root: Path | None = None) -> Path:
    root = root or _workspace()
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _write_drift_index(rows: list[dict]) -> Path:
    fd, path_str = tempfile.mkstemp(suffix=".jsonl", prefix="drift_")
    os.close(fd)
    path = Path(path_str)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"schema_version": "auditooor.hackerman_bug_class_shift.v1", "candidate_count": len(rows)}) + "\n")
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return path


def _run(draft: Path, **kwargs):
    return mod.run(draft, **kwargs)


class R38ScopeTests(unittest.TestCase):
    def test_severity_low_skips(self) -> None:
        draft = _write_draft("Severity: Low\nSelected impact: direct loss of funds\nattack_class: griefing-via-spam\n")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_no_rubric_phrase_passes(self) -> None:
        draft = _write_draft("Severity: High\nSelected impact: matching engine latency\nattack_class: timing-side-channel\n")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-rubric-phrase")

    def test_unreadable_path_returns_error(self) -> None:
        rc, payload = _run(Path("/no/such/file.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


class R38RubricAlignmentTests(unittest.TestCase):
    def test_rubric_matches_attack_class_passes(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds via unauthorised redemption\n"
            "attack_class: theft-via-reentrancy\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")

    def test_rubric_mismatches_attack_class_fails(self) -> None:
        # Genuine IMPOSSIBLE combo (preserved drift): a precision-loss/rounding mechanism
        # cannot cause a permanent FREEZE of funds (precision -> theft/yield/precision,
        # never freeze). Universal bridge still rejects this.
        body = (
            "Severity: High\n"
            "Selected impact: permanent freezing of position-collateral\n"
            "attack_class: precision-loss-rounding-dust\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-rubric-attack-class-mismatch")

    def test_rubric_mismatch_with_rebuttal_passes(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: permanent freezing of position-collateral\n"
            "attack_class: governance-takeover-via-admin-key\n"
            "<!-- r38-rebuttal: admin-key seizure intersects freeze-and-governance; cite operator_overrides/wave2.yaml -->\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("admin-key seizure", payload["rebuttal"])

    def test_oversize_rebuttal_fails(self) -> None:
        big = "x" * 250
        body = (
            "Severity: High\n"
            "Selected impact: permanent freezing of position-collateral\n"
            "attack_class: precision-loss-rounding-dust\n"
            f"<!-- r38-rebuttal: {big} -->\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 1, payload)
        self.assertTrue(payload.get("rebuttal_oversize"))
        self.assertEqual(payload["verdict"], "fail-rubric-attack-class-mismatch")

    def test_critical_severity_path(self) -> None:
        body = (
            "Severity: Critical\n"
            "Selected impact: direct loss of funds via vault drain\n"
            "attack_class: theft-via-share-rounding\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")
        self.assertEqual(payload["severity_observed"], "critical")

    def test_multiple_rubric_phrases_set_union(self) -> None:
        # "direct loss of funds" -> theft; "griefing" -> griefing
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds with griefing side-effect\n"
            "attack_class: griefing-via-fee-spam\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, allow_missing_index=True)
        # griefing class falls in the expected union -> pass.
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")
        self.assertTrue(set(payload["expected_impact_class"]) >= {"theft", "griefing"})

    def test_attack_class_missing_treated_as_mismatch(self) -> None:
        body = "Severity: High\nSelected impact: direct loss of funds\n"
        draft = _write_draft(body)
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-rubric-attack-class-mismatch")
        self.assertTrue(payload.get("attack_class_missing"))


class R38DriftIndexTests(unittest.TestCase):
    def test_corpus_citation_drift_unacknowledged_fails(self) -> None:
        drift = _write_drift_index([
            {
                "record_id": "sherlock:2024-02-mento-judging:003:31f8180e616b",
                "drift_category": "rubric_row_vs_impact_class_mismatch",
                "subtree": "contest_platform_findings",
            }
        ])
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: theft-via-rounding\n"
            "Citation: `sherlock:2024-02-mento-judging:003:31f8180e616b` shows similar drift.\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, drift_index_path=drift)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-corpus-citation-drift-unacknowledged")
        self.assertIn("sherlock:2024-02-mento-judging:003:31f8180e616b", payload["record_ids_in_drift_index"])

    def test_corpus_citation_drift_acknowledged_passes(self) -> None:
        drift = _write_drift_index([
            {
                "record_id": "sherlock:2024-02-mento-judging:003:31f8180e616b",
                "drift_category": "rubric_row_vs_impact_class_mismatch",
                "subtree": "contest_platform_findings",
            }
        ])
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: theft-via-rounding\n"
            "Citation: `sherlock:2024-02-mento-judging:003:31f8180e616b` is a bug-class-shift candidate\n"
            "(drift acknowledged; cited for shape only).\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, drift_index_path=drift)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-corpus-citation-acknowledged")

    def test_index_missing_with_allow_returns_pass_path(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: theft-via-rounding\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(
            draft, drift_index_path=Path("/no/such/index.jsonl"), allow_missing_index=True
        )
        self.assertEqual(rc, 0, payload)
        # Falls through to rubric-match verdict.
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")
        self.assertTrue(payload.get("drift_index_missing"))


class R38MechanismImpactBridgeTests(unittest.TestCase):
    """UNIVERSAL mechanism->impact bridge (NUVA 2026-06-30): SCOPE is the IMPACT a
    finding achieves, not the mechanism LABEL. A mechanism-labelled attack_class PASSES
    against any impact it CAN achieve (overflow->freeze, access-control->theft,
    reentrancy->theft, halt->freeze) and FAILS only the IMPOSSIBLE combos that preserve
    drift detection (halt->theft, griefing->theft, precision-loss->governance, and
    read-only/view reentrancy->theft/freeze)."""

    def test_chain_halt_against_permanent_freeze_passes(self) -> None:
        body = (
            "Severity: Critical\n"
            "Selected impact: permanent freezing of funds\n"
            "attack_class: chain-halt\n"
        )
        draft = _write_draft(body, filename="halt-freeze-CRIT.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")

    def test_dos_against_temporary_freeze_passes(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: freezing of funds (temporary)\n"
            "attack_class: gas-exhaustion-dos\n"
        )
        draft = _write_draft(body, filename="dos-tempfreeze-HIGH.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)

    def test_denial_family_does_not_bridge_to_theft(self) -> None:
        # a halt cannot DIRECTLY steal; halt vs a theft rubric must still fail (precise).
        body = (
            "Severity: Critical\n"
            "Selected impact: direct theft of user funds\n"
            "attack_class: chain-halt\n"
        )
        draft = _write_draft(body, filename="halt-theft-CRIT.md")
        rc, payload = _run(draft, allow_missing_index=True, strict=True)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-rubric-attack-class-mismatch")

    def test_bridge_unit_function(self) -> None:
        f = mod._attack_class_matches_expected
        # PLAUSIBLE combos now PASS (mechanism != impact; scope is the achieved impact).
        self.assertTrue(f("chain-halt", {"freeze"}))
        self.assertTrue(f("denial-of-service", {"dos"}))
        self.assertTrue(f("arithmetic-overflow", {"freeze"}))   # overflow CAN freeze
        self.assertTrue(f("access-control-missing", {"theft"}))  # missing auth CAN steal
        self.assertTrue(f("reentrancy-cross-function", {"theft"}))  # reentrancy CAN steal
        # IMPOSSIBLE combos still FAIL (drift detection preserved).
        self.assertFalse(f("chain-halt", {"theft"}))            # halt cannot steal
        self.assertFalse(f("griefing-via-spam", {"theft"}))     # griefing != capture
        self.assertFalse(f("precision-loss-dust", {"governance-takeover"}))
        self.assertFalse(f("read-only-reentrancy", {"theft"}))  # view-only != in-scope theft
        self.assertFalse(f("reentrancy-read-only", {"freeze"}))  # ordering-robust


class R38MechanismImpactEnvOverrideTests(unittest.TestCase):
    def test_env_extends_mechanism_bridge(self) -> None:
        f = mod._attack_class_matches_expected
        # An UNKNOWN mechanism is not bridged by default; the env override registers it.
        self.assertFalse(f("custom-quantum-glitch", {"freeze"}))  # not in the table
        os.environ["AUDITOOOR_R38_MECHANISM_IMPACTS"] = "custom-quantum-glitch=theft|freeze"
        try:
            self.assertTrue(f("custom-quantum-glitch", {"freeze"}))
        finally:
            os.environ.pop("AUDITOOOR_R38_MECHANISM_IMPACTS", None)


class R38EnvOverrideTests(unittest.TestCase):
    def test_env_override_extends_rubric_table(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: theft via reentrancy in vault claim path\n"
            "attack_class: theft-via-reentrancy\n"
        )
        draft = _write_draft(body)
        os.environ["AUDITOOOR_R38_RUBRIC_TO_IMPACT_OVERRIDES"] = "theft via reentrancy=>theft"
        try:
            rc, payload = _run(draft, allow_missing_index=True)
        finally:
            os.environ.pop("AUDITOOOR_R38_RUBRIC_TO_IMPACT_OVERRIDES", None)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")
        self.assertIn("theft via reentrancy", payload["rubric_phrases_observed"])


# ---------------------------------------------------------------------------
# Wave-2 PR-A fixture expansion (per Wave-2 W29 brief, 2026-05-16).
# synthetic_fixture: true
#
# Adds coverage for: cross-language same-class shift, adjacent-class shift
# inside same family, hard cross-family shift, empty-class-on-one-side,
# multi-class on one side, tier-1 vs tier-5 evidence shift (drift-row
# severity-tier annotations), quarantine-subtree drift rows, and rebuttal
# marker integration. All synthetic fixtures use the
# auditooor.hackerman_bug_class_shift.v1 envelope.
# ---------------------------------------------------------------------------


class R38CrossLanguageShiftTests(unittest.TestCase):
    """Cross-language same-class shift: Solidity vs Rust same family.

    Both attack_class values map to the same expected impact bucket
    (``theft``), so the gate should PASS for both regardless of the
    language token in the attack_class identifier.
    synthetic_fixture: true
    """

    def test_solidity_theft_via_reentrancy_passes(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds on a Solidity vault\n"
            "attack_class: theft-via-reentrancy-sol\n"
            "language: solidity  # synthetic_fixture: true\n"
        )
        draft = _write_draft(body, filename="cross-lang-sol-HIGH.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")

    def test_rust_theft_via_reentrancy_passes(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds on a Rust ink! vault\n"
            "attack_class: theft-via-reentrancy-rs\n"
            "language: rust  # synthetic_fixture: true\n"
        )
        draft = _write_draft(body, filename="cross-lang-rs-HIGH.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")


class R38AdjacentClassShiftTests(unittest.TestCase):
    """Adjacent-class shift inside the reentrancy family.

    Universal bridge: cross-function reentrancy CAN achieve direct theft, so it PASSES
    against a ``direct loss of funds`` rubric. The READ-ONLY variant cannot directly
    steal/freeze in-scope funds (it corrupts a view another protocol reads), so it still
    FAILS - the genuine drift case the bridge must preserve.
    synthetic_fixture: true
    """

    def test_reentrancy_cross_function_against_theft_rubric_passes(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: reentrancy-cross-function\n"
            "# synthetic_fixture: true (adjacent-class)\n"
        )
        draft = _write_draft(body, filename="adj-rc-HIGH.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")

    def test_reentrancy_read_only_against_theft_rubric_fails(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: reentrancy-read-only\n"
            "# synthetic_fixture: true (adjacent-class, read-only variant)\n"
        )
        draft = _write_draft(body, filename="adj-rro-HIGH.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-rubric-attack-class-mismatch")


class R38HardCrossFamilyShiftTests(unittest.TestCase):
    """Mechanism != impact across families. Under the universal bridge a mechanism
    PASSES against any impact it can ACHIEVE: missing access-control CAN cause direct
    theft; an arithmetic overflow CAN permanently freeze. These were the wrong-expectation
    drift tests the denial-only scope left mis-rejecting; they now PASS.
    synthetic_fixture: true
    """

    def test_access_control_vs_theft_rubric_passes(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: direct theft of LP shares\n"
            "attack_class: access-control-missing-modifier\n"
            "# synthetic_fixture: true (mechanism->impact)\n"
        )
        draft = _write_draft(body, filename="cross-family-ac-HIGH.md")
        rc, payload = _run(draft, allow_missing_index=True, strict=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")

    def test_arithmetic_overflow_vs_freeze_rubric_passes(self) -> None:
        body = (
            "Severity: Critical\n"
            "Selected impact: permanent freezing of bridged collateral\n"
            "attack_class: arithmetic-overflow-on-mint\n"
            "# synthetic_fixture: true (mechanism->impact)\n"
        )
        draft = _write_draft(body, filename="cross-family-ovf-CRIT.md")
        rc, payload = _run(draft, allow_missing_index=True, strict=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")


class R38EmptyAndMultiClassTests(unittest.TestCase):
    """Empty-class-on-one-side AND multi-class on one side.

    Empty rubric (no known phrase) ``pass-no-rubric-phrase``.
    Multi-class on rubric side: union of expected sets means a single
    matching token in attack_class is sufficient.
    synthetic_fixture: true
    """

    def test_empty_rubric_known_class_passes(self) -> None:
        body = (
            "Severity: High\n"
            "Selected impact: out-of-band staking-claim mishandling (no rubric phrase)\n"
            "attack_class: theft-via-reentrancy\n"
            "# synthetic_fixture: true (empty-rubric side)\n"
        )
        draft = _write_draft(body, filename="empty-rubric-HIGH.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-no-rubric-phrase")

    def test_multi_class_rubric_one_matching_token_passes(self) -> None:
        # "permanent freezing" -> freeze; "griefing" -> griefing.
        # attack_class contains the freeze token => union match => PASS.
        body = (
            "Severity: High\n"
            "Selected impact: permanent freezing of staker rewards with griefing side-effect\n"
            "attack_class: freeze-via-uncancellable-withdraw\n"
            "# synthetic_fixture: true (multi-class rubric)\n"
        )
        draft = _write_draft(body, filename="multi-rubric-HIGH.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-matches-rubric")
        self.assertTrue(set(payload["expected_impact_class"]) >= {"freeze", "griefing"})


class R38EvidenceTierAndQuarantineTests(unittest.TestCase):
    """Drift-row evidence-tier and quarantine subtree handling.

    The R38 gate currently checks (1) rubric vs attack_class mismatch and
    (2) cited record_ids in the drift index. Drift rows may carry
    ``evidence_tier`` and ``quarantine: true`` annotations from upstream;
    the gate does not branch on tier today, so these fixtures pin the
    current behavior so a future tier-aware refactor can detect the change.
    synthetic_fixture: true
    """

    def test_tier1_drift_row_unacknowledged_fails(self) -> None:
        drift = _write_drift_index([
            {
                "record_id": "code4rena:2024-07-velodrome:001:aaaa11112222bbbb",
                "drift_category": "rubric_row_vs_impact_class_mismatch",
                "subtree": "contest_platform_findings",
                "evidence_tier": 1,
                "synthetic_fixture": True,
            }
        ])
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: theft-via-share-rounding\n"
            "Citation: `code4rena:2024-07-velodrome:001:aaaa11112222bbbb` baseline shape.\n"
        )
        draft = _write_draft(body, filename="tier1-drift-HIGH.md")
        rc, payload = _run(draft, drift_index_path=drift)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-corpus-citation-drift-unacknowledged")

    def test_tier5_drift_row_advisory_acknowledged_passes(self) -> None:
        drift = _write_drift_index([
            {
                "record_id": "immunefi:2025-01-aave-v4:042:ffeeddccbbaa9988",
                "drift_category": "rubric_row_vs_impact_class_mismatch",
                "subtree": "immunefi",
                "evidence_tier": 5,
                "synthetic_fixture": True,
            }
        ])
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: theft-via-share-rounding\n"
            "Citation: `immunefi:2025-01-aave-v4:042:ffeeddccbbaa9988` - "
            "noted as a bug-class-shift candidate (advisory tier-5 evidence; "
            "cited only for shape).\n"
        )
        draft = _write_draft(body, filename="tier5-drift-HIGH.md")
        rc, payload = _run(draft, drift_index_path=drift)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-corpus-citation-acknowledged")

    def test_quarantine_subtree_drift_row_still_fails_without_ack(self) -> None:
        """Quarantine annotation on drift row does NOT auto-exempt; pinning
        current behavior (spec defers quarantine semantics to upstream
        detector, not the gate). If future spec adds gate-side filtering,
        this test will fail and force the doctrine update.
        """
        drift = _write_drift_index([
            {
                "record_id": "sherlock:quarantine:2024-09-broken-target:001:11223344aabbccdd",
                "drift_category": "rubric_row_vs_impact_class_mismatch",
                "subtree": "_quarantine_contest_platform_findings",
                "quarantine": True,
                "synthetic_fixture": True,
            }
        ])
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: theft-via-share-rounding\n"
            "Citation: `sherlock:quarantine:2024-09-broken-target:001:11223344aabbccdd`.\n"
        )
        draft = _write_draft(body, filename="quarantine-drift-HIGH.md")
        rc, payload = _run(draft, drift_index_path=drift)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-corpus-citation-drift-unacknowledged")


class R38RebuttalIntegrationTests(unittest.TestCase):
    """Cross-cutting rebuttal-marker integration.

    Verifies that ``<!-- r38-rebuttal: ... -->`` overrides every failing
    branch (rubric mismatch, drift unacknowledged, attack_class missing).
    synthetic_fixture: true
    """

    def test_rebuttal_overrides_drift_failure(self) -> None:
        drift = _write_drift_index([
            {
                "record_id": "cantina:2025-03-some-target:013:abcdef0123456789",
                "drift_category": "rubric_row_vs_impact_class_mismatch",
                "subtree": "cantina",
                "synthetic_fixture": True,
            }
        ])
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: theft-via-rounding\n"
            "Citation: `cantina:2025-03-some-target:013:abcdef0123456789`.\n"
            "<!-- r38-rebuttal: drift citation is shape-only; operator-approved -->\n"
        )
        draft = _write_draft(body, filename="rebuttal-drift-HIGH.md")
        rc, payload = _run(draft, drift_index_path=drift)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_rebuttal_overrides_attack_class_missing(self) -> None:
        body = (
            "Severity: Critical\n"
            "Selected impact: direct loss of funds\n"
            "# no attack_class declared on purpose\n"
            "<!-- r38-rebuttal: attack_class derived from impact_contract.yaml; PR-attached -->\n"
        )
        draft = _write_draft(body, filename="rebuttal-missing-CRIT.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_rebuttal_exactly_200_chars_accepted(self) -> None:
        reason = "x" * 200
        body = (
            "Severity: High\n"
            "Selected impact: permanent freezing\n"
            "attack_class: governance-takeover-via-admin-key\n"
            f"<!-- r38-rebuttal: {reason} -->\n"
        )
        draft = _write_draft(body, filename="rebuttal-200-HIGH.md")
        rc, payload = _run(draft, allow_missing_index=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertEqual(len(payload["rebuttal"]), 200)


class R38RecordIdPlatformCoverageTests(unittest.TestCase):
    """Rule-generality: the record_id citation parser must cover every
    bounty platform the drift index can carry, not only the original four
    (code4rena / sherlock / immunefi / cantina). Adds hackenproof / hats /
    secure3 / cyfrin / spearbit, plus a generic platform-prefix fallback
    and an AUDITOOOR_R38_RECORD_ID_PLATFORMS env hook.
    """

    def test_hackenproof_record_id_is_parsed(self) -> None:
        rid = "hackenproof:2025-04-some-target:007:abcdef0123456789"
        drift = _write_drift_index([
            {
                "record_id": rid,
                "drift_category": "rubric_row_vs_impact_class_mismatch",
                "subtree": "hackenproof",
            }
        ])
        body = (
            "Severity: High\n"
            "Selected impact: direct loss of funds\n"
            "attack_class: theft-via-rounding\n"
            f"Citation: `{rid}` shows similar drift.\n"
        )
        draft = _write_draft(body, filename="hackenproof-drift-HIGH.md")
        rc, payload = _run(draft, drift_index_path=drift)
        # The hackenproof record_id is now parsed AND found in the drift
        # index, so the gate fails for unacknowledged drift (not a silent
        # pass-through).
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-corpus-citation-drift-unacknowledged")
        self.assertIn(rid, payload["record_ids_cited"])
        self.assertIn(rid, payload["record_ids_in_drift_index"])

    def test_extended_platform_prefixes_parse(self) -> None:
        for platform in ("hats", "secure3", "cyfrin", "spearbit"):
            rid = f"{platform}:2025-06-target:001:00112233aabbccdd"
            body = f"Citation: `{rid}` baseline shape.\n"
            cited = mod._extract_record_ids(body)
            self.assertIn(rid, cited, f"{platform} record_id should parse")

    def test_unknown_platform_parses_via_generic_fallback(self) -> None:
        rid = "newplatform:2026-01-target:042:deadbeefcafe1234"
        body = f"Citation: `{rid}` is a future-platform record.\n"
        cited = mod._extract_record_ids(body)
        self.assertIn(rid, cited)

    def test_env_record_id_platforms_hook(self) -> None:
        rid = "internalbounty:2026-02-target:003:fedcba9876543210"
        body = f"Citation: `{rid}` internal-platform record.\n"
        os.environ["AUDITOOOR_R38_RECORD_ID_PLATFORMS"] = "internalbounty, anotherplatform"
        try:
            cited = mod._extract_record_ids(body)
        finally:
            os.environ.pop("AUDITOOOR_R38_RECORD_ID_PLATFORMS", None)
        self.assertIn(rid, cited)


if __name__ == "__main__":
    unittest.main()
