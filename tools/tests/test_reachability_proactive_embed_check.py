"""Unit tests for Rule 60 Reachability-Proactive-Embed gate (Check #107).

Covers all pass-* and fail-* verdicts, the rebuttal short-circuit, severity
discipline, and the two live anchors:
  Anchor 1 (positive): the operator-upgraded DRILL-6 paste-ready at
    /Users/wolf/audits/hyperbridge/submissions/filed/
      pallet-relayer-u256-truncation/pallet-relayer-u256-truncation.md
    must verdict pass-reachability-section-complete.
  Anchor 2 (negative regression): a synthesized "weak" version of DRILL-6
    that keeps the Disposition uncertainty prose but strips the
    `## Reachability` section must verdict fail-no-reachability-section.

>= 20 cases.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "reachability_proactive_embed_check",
    ROOT / "tools" / "reachability-proactive-embed-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


# Anchor 1: the operator-upgraded DRILL-6 paste-ready (real file on disk).
DRILL6_PATH = Path(
    "/Users/wolf/audits/hyperbridge/submissions/filed/"
    "pallet-relayer-u256-truncation/pallet-relayer-u256-truncation.md"
)


def _draft(body: str, filename: str = "draft-MEDIUM.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="r60_test_"))
    p = root / filename
    p.write_text(body, encoding="utf-8")
    return p


def _run(
    draft: Path,
    *,
    severity: str | None = None,
    strict: bool = False,
) -> tuple[int, dict]:
    return mod.run(draft, severity_override=severity, strict=strict)


# Re-usable fragments that satisfy each of the 4 fields.
UPSTREAM_CIT = (
    "The producer entrypoint is `modules/pallets/relayer/src/withdrawal.rs:82` "
    "and is callable by an unsigned origin (any relayer; permissionless)."
)
BOUND_EVIDENCE = (
    "There is NO overflow guard at line 139 and no MAX_FEE upper-bound check. "
    "An exhaustive grep returned ZERO production-code hits for `try_into::<u128>`."
)
SINGLE_SHOT = (
    "Even one occurrence yields permanent loss; a single tx reaches the impact."
)
PRIOR_ART = (
    "Anchored by `prior_audits/DIGEST_SRL_hyperbridge_prior_audits.md:81` "
    "(SRL residual hunt area) and Cyfrin Solodit pattern for integer truncation."
)
UNCERTAINTY = (
    "- Disposition: routine reachability is an operator-only assessment, "
    "may require extraordinary accumulation; whether the attack is reachable "
    "in production is a calibration question."
)


def _full_complete_draft(severity_header: str = "- Severity: Medium") -> str:
    return (
        f"# Some integer-truncation finding\n\n"
        f"{severity_header}\n\n"
        f"## Disposition\n{UNCERTAINTY}\n\n"
        f"## Reachability\n"
        f"{UPSTREAM_CIT} {BOUND_EVIDENCE} {SINGLE_SHOT} {PRIOR_ART}\n"
    )


# ---------------------------------------------------------------------------
# Severity discipline
# ---------------------------------------------------------------------------
class TestSeverityDiscipline(unittest.TestCase):

    def test_low_severity_passes_oos(self) -> None:
        body = (
            "- Severity: Low\n\n"
            f"{UNCERTAINTY}\n"
        )
        draft = _draft(body, filename="low-draft.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_missing_severity_passes_oos(self) -> None:
        body = f"# Finding with no severity declaration\n\n{UNCERTAINTY}\n"
        draft = _draft(body, filename="nosev.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_to_low(self) -> None:
        body = "- Severity: High\n\n" + UNCERTAINTY
        draft = _draft(body, filename="hi.md")
        rc, payload = _run(draft, severity="Low")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


# ---------------------------------------------------------------------------
# Pass: no uncertainty prose (escalation pre-built)
# ---------------------------------------------------------------------------
class TestPassNoUncertaintyProse(unittest.TestCase):

    def test_pre_built_disposition_passes(self) -> None:
        body = (
            "- Severity: High\n\n"
            "## Disposition\n"
            "Critical severity - direct loss of funds via a deterministic "
            "exploit reachable on the production deployment.\n"
        )
        draft = _draft(body, filename="prebuilt.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-uncertainty-prose")

    def test_medium_with_no_hedge_words_passes(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            "Standard bounded arithmetic issue; the impact is deterministic.\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-uncertainty-prose")


# ---------------------------------------------------------------------------
# Pass: complete reachability section
# ---------------------------------------------------------------------------
class TestPassComplete(unittest.TestCase):

    def test_full_complete_medium_passes(self) -> None:
        draft = _draft(_full_complete_draft())
        rc, payload = _run(draft)
        self.assertEqual(rc, 0, msg=payload.get("reason"))
        self.assertEqual(payload["verdict"], "pass-reachability-section-complete")

    def test_full_complete_high_passes(self) -> None:
        draft = _draft(_full_complete_draft("- Severity: High"))
        rc, payload = _run(draft)
        self.assertEqual(rc, 0, msg=payload.get("reason"))
        self.assertEqual(payload["verdict"], "pass-reachability-section-complete")

    def test_inline_reachability_header_form_passes(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "Reachability - "
            f"{UPSTREAM_CIT} {BOUND_EVIDENCE} {SINGLE_SHOT} {PRIOR_ART}\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 0, msg=payload.get("reason"))
        self.assertEqual(payload["verdict"], "pass-reachability-section-complete")

    def test_reachability_trace_header_also_matches(self) -> None:
        # `## Reachability Trace` should satisfy the section-presence regex
        # (`^##\s*reachability`).
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Reachability Trace\n"
            f"{UPSTREAM_CIT} {BOUND_EVIDENCE} {SINGLE_SHOT} {PRIOR_ART}\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 0, msg=payload.get("reason"))
        self.assertEqual(payload["verdict"], "pass-reachability-section-complete")


# ---------------------------------------------------------------------------
# Rebuttal short-circuit
# ---------------------------------------------------------------------------
class TestRebuttal(unittest.TestCase):

    def test_visible_line_rebuttal_passes(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "r60-rebuttal: always-reachable structural arithmetic bug; "
            "no reachability question applies.\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_html_comment_rebuttal_passes(self) -> None:
        body = (
            "- Severity: High\n\n"
            f"{UNCERTAINTY}\n\n"
            "<!-- r60-rebuttal: external-platform request to omit reachability detail "
            "per operator decision -->\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_oversized_rebuttal_ignored_fails(self) -> None:
        too_long = "x" * 250
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            f"<!-- r60-rebuttal: {too_long} -->\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        # Oversized -> rebuttal is ignored, original fail path returns
        # fail-no-reachability-section (no section in the body).
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-reachability-section")


# ---------------------------------------------------------------------------
# Fail: no reachability section
# ---------------------------------------------------------------------------
class TestFailNoSection(unittest.TestCase):

    def test_uncertainty_without_section_fails(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            "## Disposition\n"
            "This is an operator-only assessment; whether the attack is "
            "reachable in production depends on accumulation.\n\n"
            "## Summary\n"
            "Bug exists at modules/foo.rs:42 and we have details to share.\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-reachability-section")

    def test_uncertainty_with_only_unrelated_sections_fails(self) -> None:
        body = (
            "- Severity: High\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Source-level proof\n\nfoo.go:11\n\n"
            "## Impact Contract\n\nbar.\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-reachability-section")


# ---------------------------------------------------------------------------
# Fail: missing each individual field
# ---------------------------------------------------------------------------
class TestFailMissingFields(unittest.TestCase):

    def test_missing_upstream_citation(self) -> None:
        # No actor-control keyword, only file:line.
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Reachability\n"
            "Producer at modules/relayer.rs:82.\n"
            f"{BOUND_EVIDENCE} {SINGLE_SHOT} {PRIOR_ART}\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-upstream-citation")

    def test_missing_upstream_citation_no_file_line(self) -> None:
        # Actor-control keyword present but no file:line.
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Reachability\n"
            "The producer is permissionless (anyone can call). "
            f"{BOUND_EVIDENCE} {SINGLE_SHOT} {PRIOR_ART}\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-upstream-citation")

    def test_missing_bound_evidence(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Reachability\n"
            f"{UPSTREAM_CIT} The arithmetic happens at withdrawal.rs:139.\n"
            f"{SINGLE_SHOT} {PRIOR_ART}\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-bound-evidence")

    def test_missing_single_shot(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Reachability\n"
            f"{UPSTREAM_CIT} {BOUND_EVIDENCE} {PRIOR_ART}\n"
            "Many sustained events required over time.\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-single-shot-scenario")

    def test_missing_prior_art(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Reachability\n"
            f"{UPSTREAM_CIT} {BOUND_EVIDENCE} {SINGLE_SHOT}\n"
            "No reference to external exploit class is included.\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-prior-art-anchor")


# ---------------------------------------------------------------------------
# Prior-art variants
# ---------------------------------------------------------------------------
class TestPriorArtVariants(unittest.TestCase):

    def test_cve_anchor_matches(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Reachability\n"
            f"{UPSTREAM_CIT} {BOUND_EVIDENCE} {SINGLE_SHOT} "
            "Anchored by CVE-2024-12345 with similar root cause.\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-reachability-section-complete")

    def test_ghsa_anchor_matches(self) -> None:
        body = (
            "- Severity: High\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Reachability\n"
            f"{UPSTREAM_CIT} {BOUND_EVIDENCE} {SINGLE_SHOT} "
            "See GHSA-abcd-efgh-ijkl for analogous prior incident.\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-reachability-section-complete")

    def test_trail_of_bits_anchor_matches(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n\n"
            "## Reachability\n"
            f"{UPSTREAM_CIT} {BOUND_EVIDENCE} {SINGLE_SHOT} "
            "Trail of Bits post-mortem 2024 covers the same exploit class.\n"
        )
        draft = _draft(body)
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-reachability-section-complete")

    def test_env_extension_prior_art(self) -> None:
        os.environ["AUDITOOOR_R60_PRIOR_ART_PATTERNS"] = r"\bPolytope[- ]custom[- ]anchor\b"
        try:
            body = (
                "- Severity: Medium\n\n"
                f"{UNCERTAINTY}\n\n"
                "## Reachability\n"
                f"{UPSTREAM_CIT} {BOUND_EVIDENCE} {SINGLE_SHOT} "
                "Polytope-custom-anchor justifies this finding.\n"
            )
            draft = _draft(body)
            rc, payload = _run(draft)
            self.assertEqual(rc, 0)
            self.assertEqual(payload["verdict"], "pass-reachability-section-complete")
        finally:
            os.environ.pop("AUDITOOOR_R60_PRIOR_ART_PATTERNS", None)


# ---------------------------------------------------------------------------
# Env extension for uncertainty triggers
# ---------------------------------------------------------------------------
class TestUncertaintyEnvExtension(unittest.TestCase):

    def test_custom_uncertainty_trigger(self) -> None:
        # Without the env extension, this body has no uncertainty prose.
        body = (
            "- Severity: Medium\n\n"
            "## Disposition\nNeeds-platform-evaluation only.\n"
        )
        draft = _draft(body, filename="custom1.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-uncertainty-prose")

        os.environ["AUDITOOOR_R60_UNCERTAINTY_PATTERNS"] = r"\bneeds[- ]platform[- ]evaluation\b"
        try:
            draft2 = _draft(body, filename="custom2.md")
            rc, payload = _run(draft2)
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "fail-no-reachability-section")
        finally:
            os.environ.pop("AUDITOOOR_R60_UNCERTAINTY_PATTERNS", None)


# ---------------------------------------------------------------------------
# Anchor 1: live DRILL-6 paste-ready passes
# ---------------------------------------------------------------------------
class TestDrill6LiveAnchor(unittest.TestCase):

    @unittest.skipUnless(
        DRILL6_PATH.exists(),
        f"DRILL-6 upgraded paste-ready not present at {DRILL6_PATH}; skipping live anchor",
    )
    def test_drill6_upgraded_passes(self) -> None:
        rc, payload = _run(DRILL6_PATH, severity="Medium")
        self.assertEqual(
            rc, 0,
            msg=f"R60 expected pass on DRILL-6 upgraded but got "
                f"verdict={payload.get('verdict')!r} reason={payload.get('reason')!r}",
        )
        self.assertEqual(payload["verdict"], "pass-reachability-section-complete")


# ---------------------------------------------------------------------------
# Anchor 2: synthesized weak version of DRILL-6 fails
# ---------------------------------------------------------------------------
class TestDrill6WeakSynth(unittest.TestCase):
    """Anchor 2 (negative regression): same Disposition uncertainty prose as
    DRILL-6's pre-upgrade form, but no Reachability section embedded inline.
    Must verdict fail-no-reachability-section.
    """

    def test_synth_weak_drill6_fails(self) -> None:
        body = (
            "# Integer truncation in pallet-ismp-relayer::withdraw_fees\n\n"
            "- Severity: Medium\n\n"
            "## Disposition\n"
            "Medium - the bug is real but routine reachability is an "
            "operator-only assessment; whether the relayer population can "
            "reach `accrued > u128::MAX` in production is a calibration "
            "question that depends on accumulation. May not be reachable "
            "under default deployment without degenerate upstream.\n\n"
            "## Summary\n"
            "Bug at modules/pallets/relayer/src/withdrawal.rs:139 via `low_u128()`.\n"
            "There is NO overflow guard at line 139.\n"
        )
        draft = _draft(body, filename="hb-pallet-relayer-u256-truncation-weak.md")
        rc, payload = _run(draft, severity="Medium")
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-reachability-section")


# ---------------------------------------------------------------------------
# JSON schema sanity
# ---------------------------------------------------------------------------
class TestSchemaSanity(unittest.TestCase):

    def test_pass_payload_has_schema(self) -> None:
        draft = _draft(_full_complete_draft())
        _, payload = _run(draft)
        self.assertEqual(payload["schema_version"], "auditooor.r60_reachability_proactive_embed.v1")
        self.assertEqual(payload["gate"], "R60-REACHABILITY-PROACTIVE-EMBED")
        self.assertIn("evidence", payload)

    def test_fail_payload_has_schema(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            f"{UNCERTAINTY}\n"
        )
        draft = _draft(body)
        _, payload = _run(draft)
        self.assertEqual(payload["schema_version"], "auditooor.r60_reachability_proactive_embed.v1")
        self.assertEqual(payload["gate"], "R60-REACHABILITY-PROACTIVE-EMBED")
        self.assertIn("verdict", payload)


if __name__ == "__main__":
    unittest.main()
