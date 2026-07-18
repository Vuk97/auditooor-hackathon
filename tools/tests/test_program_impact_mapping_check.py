#!/usr/bin/env python3
"""Tests for tools/program-impact-mapping-check.py (PR #526 gap 0).

Hermetic: each test builds a throwaway workspace under ``tempfile`` with
synthetic SEVERITY.md + drafts under ``submissions/staging/``.

Coverage map (Check #31, PR #526 gap 0):

    test_critical_without_mapping_block_fails
    test_critical_with_complete_mapping_passes
    test_critical_with_invented_impact_fails_rubric_grounding
    test_high_without_mapping_block_fails
    test_medium_without_mapping_fails
    test_medium_with_exact_mapping_passes
    test_low_without_mapping_passes
    test_informational_without_mapping_passes
    test_paste_ready_low_requires_mapping
    test_not_proven_impacts_empty_list_passes
    test_not_proven_impacts_missing_fails
    test_workspace_without_severity_returns_advisory_rc2
    test_severity_implied_mismatch_fails
    test_proof_artifact_missing_on_disk_fails
    test_explicit_draft_arg_works

    # FN7 regression tests (CRITICAL):
    test_fn7_critical_claim_without_mapping_fails
    test_fn7_high_claim_with_high_tier_mapping_passes
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from importlib import util as importlib_util
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_MODULE_PATH = _REPO_ROOT / "tools" / "program-impact-mapping-check.py"


def _load_module():
    name = "program_impact_mapping_check_under_test"
    spec = importlib_util.spec_from_file_location(name, str(_MODULE_PATH))
    assert spec and spec.loader
    module = importlib_util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


_MOD = _load_module()


# Canonical synthetic severity rubric. The selected_impact string in any
# passing draft must appear verbatim in this text.
_SEVERITY_MD = """\
# SEVERITY -- Synthetic Program Rubric (test fixture)

## Critical-tier listed impacts
- Total network shutdown of the canonical chain
- Hardfork-required chain split affecting all validators
- Permanent freezing of user funds inside in-scope contracts (>10%)
- Direct theft from in-scope bridge contracts (>=10% of locked value)

## High-tier listed impacts
- Engine API request validation bypass causing peer ban / fork follow-on
- Liveness regression on a single validator (recoverable, requires restart)
- Temporary freezing of user funds (recoverable within a finalization window)

## Medium-tier listed impacts
- Griefing of a single RPC endpoint
- Log misformatting that disturbs monitoring tooling
"""


def _write_workspace(root: Path, severity_text: str = _SEVERITY_MD) -> Path:
    (root / "SEVERITY.md").write_text(severity_text, encoding="utf-8")
    (root / "OOS_CHECKLIST.md").write_text("# OOS\n", encoding="utf-8")
    (root / "submissions" / "staging").mkdir(parents=True, exist_ok=True)
    return root


def _write_draft(ws: Path, name: str, body: str) -> Path:
    p = ws / "submissions" / "staging" / name
    p.write_text(body, encoding="utf-8")
    return p


def _run(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = _MOD.main(argv)
    return rc, buf.getvalue()


# ---------------------------------------------------------------------------
# Helpers for constructing draft bodies
# ---------------------------------------------------------------------------


def _draft_with_severity(sev: str, mapping_block: str | None = None, extra: str = "") -> str:
    body = f"# {sev}: synthetic finding\n\n**Severity:** {sev}\n\nBody text.\n"
    if extra:
        body += extra + "\n"
    if mapping_block:
        body += "\n" + mapping_block + "\n"
    return body


def _good_critical_block(proof_path: str = "poc/synth_proof.txt") -> str:
    return f"""## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Total network shutdown of the canonical chain
- severity_implied: Critical
- proof_artifact: {proof_path}
- not_proven_impacts: []
"""


def _good_high_block(proof_path: str = "poc/synth_proof.txt") -> str:
    return f"""## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Engine API request validation bypass causing peer ban / fork follow-on
- severity_implied: High
- proof_artifact: {proof_path}
- not_proven_impacts:
  - Total network shutdown of the canonical chain
  - Hardfork-required chain split affecting all validators
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class ProgramImpactMappingCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _write_workspace(self.ws)
        # default proof artifact on disk
        (self.ws / "poc").mkdir(exist_ok=True)
        (self.ws / "poc" / "synth_proof.txt").write_text("synthetic proof\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # --- core behaviour --------------------------------------------------

    def test_critical_without_mapping_block_fails(self):
        d = _write_draft(self.ws, "f1.md", _draft_with_severity("Critical"))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("missing `## Program Impact Mapping` block", out)

    def test_critical_with_complete_mapping_passes(self):
        d = _write_draft(self.ws, "f2.md", _draft_with_severity("Critical", _good_critical_block()))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)
        self.assertIn("[PASS/REQ]", out)

    def test_critical_with_invented_impact_fails_rubric_grounding(self):
        bad_block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Spontaneous reordering of the consensus alphabet
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "f3.md", _draft_with_severity("Critical", bad_block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("rubric grounding missing", out)

    def test_high_without_mapping_block_fails(self):
        d = _write_draft(self.ws, "f4.md", _draft_with_severity("High"))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("missing `## Program Impact Mapping` block", out)

    def test_medium_without_mapping_fails(self):
        d = _write_draft(self.ws, "f5.md", _draft_with_severity("Medium"))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("missing `## Program Impact Mapping` block", out)

    def test_medium_with_exact_mapping_passes(self):
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Griefing of a single RPC endpoint
- severity_implied: Medium
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "f5b.md", _draft_with_severity("Medium", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)

    def test_low_without_mapping_passes(self):
        d = _write_draft(self.ws, "f6.md", _draft_with_severity("Low"))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)

    def test_informational_without_mapping_passes(self):
        d = _write_draft(self.ws, "f7.md", _draft_with_severity("Informational"))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)

    def test_paste_ready_low_requires_mapping(self):
        body = _draft_with_severity("Low", extra="Status: paste-ready -- ready to file")
        d = _write_draft(self.ws, "f8.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("missing `## Program Impact Mapping` block", out)

    def test_not_proven_impacts_empty_list_passes(self):
        d = _write_draft(self.ws, "f9.md", _draft_with_severity("Critical", _good_critical_block()))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)

    def test_not_proven_impacts_missing_fails(self):
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Total network shutdown of the canonical chain
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
"""
        d = _write_draft(self.ws, "f10.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("not_proven_impacts", out)

    def test_workspace_without_severity_returns_advisory_rc2(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / "OOS_CHECKLIST.md").write_text("# OOS\n", encoding="utf-8")
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "f.md").write_text(
                _draft_with_severity("Critical", _good_critical_block()), encoding="utf-8"
            )
            rc, out = _run(["--workspace", str(ws)])
            self.assertEqual(rc, 2, out)
            self.assertIn("advisory", out.lower())

    def test_severity_implied_mismatch_fails(self):
        # Critical claim in body, but severity_implied says High.
        block = _good_high_block()
        d = _write_draft(self.ws, "f11.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("contradicts draft severity claim", out)

    def test_proof_artifact_missing_on_disk_fails(self):
        block = _good_critical_block(proof_path="poc/does_not_exist.txt")
        d = _write_draft(self.ws, "f12.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("proof_artifact path does not exist", out)

    def test_explicit_draft_arg_works(self):
        d = _write_draft(self.ws, "f13.md", _draft_with_severity("Critical", _good_critical_block()))
        # Passed via --draft directly (not workspace scan)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)

    # --- FN7 regression tests --------------------------------------------

    def test_fn7_critical_claim_without_mapping_fails(self):
        """FN7-shaped draft: claims Critical Base Azul impact but no mapping block.

        Models the exact over-framing bug PR #526 gap 0 closes: a real Base
        Rust/DLT validation bug labelled `Critical candidate` without proving
        any of the listed Base Azul Immunefi Critical impacts.
        """
        body = """# FN7: Base reth-node Engine API request validation bypass

**Severity:** Critical

## Summary
Synthetic FN7 reproduction: the Engine API harness shows a request the
node will accept that should be rejected. This is real, but it does NOT
prove any listed Critical impact (network shutdown, chain split, fund
freeze, bridge loss).

paste-ready: yes

## Proof
See poc/synth_proof.txt.
"""
        d = _write_draft(self.ws, "fn7_overframed.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("missing `## Program Impact Mapping` block", out)

    def test_fn7_high_claim_with_high_tier_mapping_passes(self):
        """Same FN7 finding, downgraded to High with valid High-tier mapping.

        This proves the gate enforces TRUTH-IN-MAPPING, NOT severity downgrade:
        the High submission with a verbatim High-tier listed impact passes.
        """
        body = """# FN7: Base reth-node Engine API request validation bypass

**Severity:** High

## Summary
Engine API request validation bypass with a runnable harness. Mapped to a
High-tier listed impact (peer ban / fork follow-on). Critical-tier impacts
remain explicitly NOT proven.

## Program Impact Mapping

- program: Base Azul Immunefi audit
- asset: base-reth-node Engine API
- selected_impact: Engine API request validation bypass causing peer ban / fork follow-on
- severity_implied: High
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts:
  - Total network shutdown of the canonical chain
  - Hardfork-required chain split affecting all validators
  - Permanent freezing of user funds inside in-scope contracts (>10%)
  - Direct theft from in-scope bridge contracts (>=10% of locked value)
"""
        d = _write_draft(self.ws, "fn7_truthful.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)
        self.assertIn("[PASS/REQ]", out)

    def test_high_selected_impact_can_ground_against_gfm_table_row(self):
        """GFM table rubrics ground selected_impact by exact impact sentence cell."""
        table_rubric = """\
# SEVERITY -- Synthetic Program Rubric (table fixture)

## Critical

| ID | Listed-impact sentence (verbatim) | Reward |
|---|---|---|
| CRIT-1 | Total network shutdown of the canonical chain | cap |

## High

| ID | Listed-impact sentence (verbatim) | Reward |
|---|---|---|
| HIGH-1 | Engine API request validation bypass causing peer ban / fork follow-on | cap |

## Out of scope

| ID | Listed-impact sentence (verbatim) | Reason |
|---|---|---|
| OOS-1 | Engine API request validation bypass causing peer ban / fork follow-on | duplicate text outside tier |
"""
        _write_workspace(self.ws, table_rubric)
        d = _write_draft(self.ws, "table_high.md", _draft_with_severity("High", _good_high_block()))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)
        self.assertIn("selected_impact grounded in `High` tier row", out)

    def test_gfm_table_parser_uses_impact_column_not_id_or_reward(self):
        tiers = _MOD._parse_rubric_tiers(
            """\
## High

| ID | Listed-impact sentence (verbatim) | Reward |
|---|---|---|
| HIGH-1 | Engine API request validation bypass causing peer ban / fork follow-on | cap |
"""
        )

        self.assertEqual(
            tiers["High"],
            ["Engine API request validation bypass causing peer ban / fork follow-on"],
        )
        self.assertNotIn("HIGH-1", tiers["High"])
        self.assertNotIn("cap", tiers["High"])


# ---------------------------------------------------------------------------
# Adversarial regression tests for PR #527 follow-up (Wave 7 GG2 -- Minimax
# review hardening).
#
# Coverage:
#   BC1 (single-char rubric grounding bypass)        -- 2 tests
#   BC2 (tier-crossing not enforced)                 -- 3 tests
#   BC3 (body-only / HTML-comment Critical claims)   -- 5 tests
#   NF1 (proof_artifact accepts dirs / SEVERITY.md)  -- 3 tests
#   NF2 (not_proven_impacts: (none) sentinel)        -- 2 tests
#   NF3 (h3 Program Impact Mapping)                  -- 1 test
#   NF4 (severity_implied trailing punctuation)      -- 1 test
#   NF5 (workspace anchor preference)                -- 1 test
#   SZ2 (h3 inside block doesn't truncate)           -- 1 test
#   SZ3 (--draft with no rubric skips grounding)     -- 1 test
#   FN7 DDD2-shaped draft (multi-bullet, capped tier)-- 2 tests
# ---------------------------------------------------------------------------


class _AdversarialBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _write_workspace(self.ws)
        (self.ws / "poc").mkdir(exist_ok=True)
        (self.ws / "poc" / "synth_proof.txt").write_text("synthetic proof\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()


class BC1_RubricGroundingBypass(_AdversarialBase):
    """BC1 -- single-char / single-word selected_impact must NOT pass grounding."""

    def test_bc1_single_char_selected_impact_fails(self):
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: a
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "bc1_a.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("rubric grounding missing", out)

    def test_bc1_severity_word_only_fails(self):
        # `selected_impact: Critical` -- the word appears in rubric headings,
        # but it's not a verbatim listed impact bullet.
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Critical
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "bc1_critical.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("rubric grounding missing", out)

    def test_bc1_partial_sentence_selected_impact_fails(self):
        # Base Azul impact selection must be the exact listed sentence. A
        # plausible substring is still not enough to derive severity.
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Total network shutdown
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "bc1_partial.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("exact listed impact sentence", out)


class BC2_TierCrossing(_AdversarialBase):
    """BC2 -- Critical claim with Medium-tier rubric impact must FAIL."""

    def test_bc2_critical_claim_with_medium_impact_fails(self):
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Griefing of a single RPC endpoint
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "bc2_crit_medium.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("tier mismatch", out)
        self.assertIn("Medium", out)

    def test_bc2_high_claim_with_critical_impact_fails(self):
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Total network shutdown of the canonical chain
- severity_implied: High
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "bc2_high_crit.md", _draft_with_severity("High", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("tier mismatch", out)

    def test_bc2_critical_claim_with_critical_impact_passes(self):
        # Tier alignment must still pass.
        d = _write_draft(self.ws, "bc2_aligned.md", _draft_with_severity("Critical", _good_critical_block()))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)


class BC3_SeverityDetection(_AdversarialBase):
    """BC3 -- whole-body severity scan, HTML-comment aware, code-fence safe."""

    def test_bc3_html_comment_severity_detected(self):
        body = """# bug report

<!-- severity: Critical -->

This is a finding without an explicit Severity line.
"""
        d = _write_draft(self.ws, "bc3_html.md", body)
        rc, out = _run(["--draft", str(d)])
        # Detected as Critical -> mapping required -> missing block.
        self.assertEqual(rc, 1, out)
        self.assertIn("missing `## Program Impact Mapping` block", out)
        self.assertIn("severity=Critical", out)

    def test_bc3_bold_mid_body_critical_detected(self):
        body = """# bug report

Some intro paragraph.

This finding is **Critical** -- bridge-loss class.

(no severity line elsewhere)
"""
        d = _write_draft(self.ws, "bc3_bold.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("severity=Critical", out)

    def test_bc3_ready_to_paste_alternates_detected(self):
        # `ready to paste` (BC3 alternate) -- should trigger paste_ready.
        body = """# minor finding

**Severity:** Low

Status: ready to paste -- ready to file.
"""
        d = _write_draft(self.ws, "bc3_ready.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("paste_ready=True", out)
        self.assertIn("missing `## Program Impact Mapping` block", out)

    def test_bc3_final_paste_alternate_detected(self):
        body = """# bug report

**Severity:** Low

Status: FINAL PASTE
"""
        d = _write_draft(self.ws, "bc3_final.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("paste_ready=True", out)

    def test_bc3_code_fence_critical_not_false_fire(self):
        # Critical inside a fenced code block must NOT trigger detection.
        body = """# routine doc

This is a documentation update. No severity claim.

Example payload (in code block):

```
**Severity:** Critical
This is a Critical bug.
```

End of doc.
"""
        d = _write_draft(self.ws, "bc3_fence.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)
        # severity should be empty (no claim outside fences)
        self.assertIn("severity=-", out)

    def test_bc3_narrative_critical_not_false_fire_when_explicit_high_present(self):
        # When `**Severity:** High` is the explicit line, body narrative
        # like "Critical is NOT recommended" must NOT promote to Critical.
        body = """# FN7-style finding

**Severity:** High

## Summary
Critical is NOT recommended for this finding because the fault-proof catch-net
prevents L1 finalization. High is the recommended posture.

## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Engine API request validation bypass causing peer ban / fork follow-on
- severity_implied: High
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts:
  - Total network shutdown of the canonical chain
"""
        d = _write_draft(self.ws, "bc3_narrative.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)
        self.assertIn("severity=High", out)


class NF1_ProofArtifactValidation(_AdversarialBase):
    def test_nf1_directory_rejected(self):
        # proof_artifact pointing at the workspace itself.
        block = _good_critical_block(proof_path=".")
        d = _write_draft(self.ws, "nf1_dir.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("proof_artifact", out)

    def test_nf1_severity_md_rejected(self):
        block = _good_critical_block(proof_path="SEVERITY.md")
        d = _write_draft(self.ws, "nf1_sev.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("proof_artifact", out)

    def test_nf1_outside_workspace_rejected(self):
        # Absolute path to /tmp -- must not pass workspace-rooted check.
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("foo")
            outside = f.name
        try:
            block = _good_critical_block(proof_path=outside)
            d = _write_draft(self.ws, "nf1_outside.md", _draft_with_severity("Critical", block))
            rc, out = _run(["--draft", str(d)])
            self.assertEqual(rc, 1, out)
            self.assertIn("proof_artifact", out)
        finally:
            os.unlink(outside)


class NF2_NotProvenSentinels(_AdversarialBase):
    def test_nf2_none_sentinel_treated_as_empty(self):
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Total network shutdown of the canonical chain
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: (none)
"""
        d = _write_draft(self.ws, "nf2_none.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        # Field is "present" semantically -- gate passes but emits a warning
        # because empty not_proven_impacts on a Critical claim is suspicious.
        self.assertEqual(rc, 0, out)
        self.assertIn("not_proven_impacts", out)

    def test_nf2_tbd_sentinel_treated_as_empty(self):
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Total network shutdown of the canonical chain
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: TBD
"""
        d = _write_draft(self.ws, "nf2_tbd.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)
        self.assertIn("empty", out.lower())


class NF3_HeadingLevels(_AdversarialBase):
    def test_nf3_h3_block_accepted_with_warning(self):
        block = """### Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Total network shutdown of the canonical chain
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "nf3_h3.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)
        self.assertIn("h3", out.lower())


class NF4_SeverityImpliedPunctuation(_AdversarialBase):
    def test_nf4_trailing_period_normalised(self):
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset
- selected_impact: Total network shutdown of the canonical chain
- severity_implied: Critical.
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "nf4_period.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)


class NF5_WorkspaceAnchorPreference(unittest.TestCase):
    def test_nf5_oos_checklist_wins_over_severity_only(self):
        # nested directory has SEVERITY.md but a parent dir has
        # OOS_CHECKLIST.md -- parent should win.
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "OOS_CHECKLIST.md").write_text("# OOS\n", encoding="utf-8")
            (root / "SEVERITY.md").write_text(_SEVERITY_MD, encoding="utf-8")
            (root / "submissions" / "staging").mkdir(parents=True)
            (root / "poc").mkdir()
            (root / "poc" / "synth_proof.txt").write_text("p\n", encoding="utf-8")
            # Nested mirror with stale SEVERITY.md
            nested = root / "submissions" / "packaged" / "subprog"
            nested.mkdir(parents=True)
            (nested / "SEVERITY.md").write_text(
                "# stale\n## Critical\n- Obsolete impact\n", encoding="utf-8"
            )
            d = nested / "f.md"
            d.write_text(
                _draft_with_severity("Critical", _good_critical_block()),
                encoding="utf-8",
            )
            rc, out = _run(["--draft", str(d)])
            # Workspace resolution should reach parent root with OOS_CHECKLIST,
            # not stop at the nested SEVERITY-only dir.
            self.assertEqual(rc, 0, out)


class DraftDiscoveryGeneratedSidecars(unittest.TestCase):
    def test_generated_oos_sidecars_are_not_submission_drafts(self):
        from tools.lib.program_impact_mapping import discover_workspace_drafts

        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            d = root / "submissions" / "final_cantina_paste"
            d.mkdir(parents=True)
            (d / "candidate.md").write_text("Severity: Medium\n", encoding="utf-8")
            (d / "OOS_CHECK.md").write_text("# generated\n", encoding="utf-8")
            (d / "candidate.OOS_CHECK.md").write_text("# generated\n", encoding="utf-8")

            drafts = discover_workspace_drafts(root)

            self.assertEqual([p.name for p in drafts], ["candidate.md"])


class SZ2_BlockExtraction(_AdversarialBase):
    def test_sz2_h3_inside_block_does_not_truncate(self):
        block = """## Program Impact Mapping

- program: Synthetic Test Program
- asset: synthetic-test-asset

### Notes

(extra commentary at h3 inside the block)

- selected_impact: Total network shutdown of the canonical chain
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "sz2_h3_inside.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)


class SZ3_GroundingWithoutRubric(unittest.TestCase):
    def test_sz3_draft_without_rubric_skips_grounding(self):
        # Draft passed via --draft, workspace has no SEVERITY*.md.
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "OOS_CHECKLIST.md").write_text("# OOS\n", encoding="utf-8")
            (root / "submissions" / "staging").mkdir(parents=True)
            (root / "poc").mkdir()
            (root / "poc" / "synth_proof.txt").write_text("p\n", encoding="utf-8")
            d = root / "submissions" / "staging" / "f.md"
            d.write_text(
                _draft_with_severity("Critical", _good_critical_block()),
                encoding="utf-8",
            )
            rc, out = _run(["--draft", str(d)])
            # No rubric -> SZ3 warning -> skip grounding -> still passes.
            self.assertEqual(rc, 0, out)
            self.assertIn("SZ3", out)


# ---------------------------------------------------------------------------
# FN7 DDD2-shaped regression tests (multi-bullet selected_impact + capped
# tier scenarios).
# ---------------------------------------------------------------------------


_SEVERITY_DDD2 = """\
# SEVERITY -- Multi-tier with operator-brief Critical (DDD2 fixture)

## 2. Operator-brief Critical impacts
- Chain-level fork or CL/EL state divergence

## 3. Immunefi v2.3 -- Blockchain / DLT

### Critical
- Total network shutdown of the canonical chain

### High
- Unintended chain split (network partition)
- Engine API request validation bypass causing peer ban / fork follow-on

### Medium
- Griefing of a single RPC endpoint
"""


class FN7_DDD2_MultiBullet(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _write_workspace(self.ws, severity_text=_SEVERITY_DDD2)
        (self.ws / "poc").mkdir(exist_ok=True)
        (self.ws / "poc" / "synth_proof.txt").write_text("p\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_fn7_ddd2_high_with_capped_secondary_passes(self):
        # DDD2 shape: severity_implied=High, selected_impact has TWO sub-bullets
        # (a PRIMARY operator-brief Critical capped to High, plus a SECONDARY
        # generic-rubric High row). The High-tier secondary must ground.
        body = """# FN7 DDD2 staging draft

**Severity (RECOMMENDED):** **High** with explicit Program Impact Mapping.

## Program Impact Mapping

- **program**: Base Azul Immunefi audit competition
- **asset**: base-reth-node Engine API
- **selected_impact**:
  - PRIMARY (program-specific brief, capped to High): **"Chain-level fork or CL/EL state divergence"** (verbatim from `SCOPE.md` "Critical impact (primary)")
  - SECONDARY (Immunefi v2.3 BDL High closest match): **"Unintended chain split (network partition)"** (verbatim from `SEVERITY.md` Section 3 BDL High row 1)
- **severity_implied**: **High**.
- **proof_artifact**:
  - poc/synth_proof.txt -- primary harness log
- **not_proven_impacts** (explicitly NOT proven, anchoring why this is High not Critical):
  - "Total network shutdown of the canonical chain"
"""
        d = _write_draft(self.ws, "fn7_ddd2.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)
        self.assertIn("[PASS/REQ]", out)

    def test_fn7_ddd2_critical_retag_with_high_impact_fails_tier_mismatch(self):
        # Same DDD2 draft retagged Critical with the same High-tier text
        # MUST FAIL with tier mismatch.
        body = """# FN7 DDD2 retagged Critical

**Severity:** Critical

## Program Impact Mapping

- program: Base Azul Immunefi audit competition
- asset: base-reth-node Engine API
- selected_impact: Unintended chain split (network partition)
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "fn7_ddd2_retag.md", body)
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("tier mismatch", out)
        self.assertIn("High", out)


class ImpactMethodologyReconciliationTests(unittest.TestCase):
    """WIRING_SPEC item D -- impact_hunting_methodology <-> Check #31.

    Non-vacuous: asserts the doc-only reconciliation constant
    ``IMPACT_METHODOLOGY_TO_CHECK31`` keeps the per-impact hunting taxonomy
    (32 ``impact_id``s) and the Check #31 tier vocabulary ON ONE AXIS rather
    than forked. Every value's tier MUST be a real Check #31 severity tier and
    every key MUST be a hyphen-cased slug with a non-empty rubric_row_hint.
    """

    def test_mapping_is_present_and_well_formed(self):
        m = _MOD.IMPACT_METHODOLOGY_TO_CHECK31
        self.assertIsInstance(m, dict)
        # The mined-set is exactly 32 impact_ids (TAXONOMY.json).
        self.assertEqual(len(m), 32, sorted(m))
        slug_re = __import__("re").compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
        for impact_id, value in m.items():
            self.assertRegex(impact_id, slug_re, f"impact_id not a slug: {impact_id}")
            self.assertIsInstance(value, tuple, impact_id)
            self.assertEqual(len(value), 2, impact_id)
            tier, hint = value
            # Reconciliation core: every tier is a real Check #31 impact class.
            self.assertIn(
                tier,
                _MOD.VALID_SEVERITIES,
                f"{impact_id} maps to tier {tier!r} not in VALID_SEVERITIES "
                f"{_MOD.VALID_SEVERITIES} -- the two taxonomies have forked",
            )
            self.assertIn(tier, _MOD.TIER_NAMES, impact_id)
            self.assertTrue(hint and hint.strip(), f"empty rubric_row_hint: {impact_id}")
            # No em-dashes / en-dashes anywhere in the reconciliation strings.
            self.assertNotIn("—", hint, impact_id)
            self.assertNotIn("–", hint, impact_id)
            self.assertNotIn("—", impact_id, impact_id)

    def test_mapping_covers_every_canonical_impact_id(self):
        # The 33-line WIRING_SPEC enumeration includes ``reentrancy`` which has
        # no standalone *.yaml file; TAXONOMY.json (the authoritative count) is
        # 32. Assert the mined-set slugs are present so the constant cannot
        # silently drop one.
        m = _MOD.IMPACT_METHODOLOGY_TO_CHECK31
        for required in (
            "direct-theft-funds",
            "protocol-insolvency",
            "permanent-freeze-funds",
            "temporary-freeze-funds",
            "theft-unclaimed-yield",
            "permanent-freeze-yield",
            "reentrancy",
            "access-control-bypass",
            "unauthorized-upgrade-impl-swap",
            "dispute-game-resolution",
        ):
            self.assertIn(required, m)

    def test_mapping_matches_taxonomy_json_when_reachable(self):
        # Cross-verify against the on-disk TAXONOMY.json source so the constant
        # cannot drift from its provenance. Skip cleanly if the corpus dir is
        # not present in this checkout (the gate is generic / repo-portable).
        candidates = [
            _REPO_ROOT
            / "agent_outputs"
            / "impact_methodology_full_2026-06-28"
            / "TAXONOMY.json",
            Path("/Users/wolf/auditooor-mcp")
            / "agent_outputs"
            / "impact_methodology_full_2026-06-28"
            / "TAXONOMY.json",
        ]
        tax_path = next((p for p in candidates if p.exists()), None)
        if tax_path is None:
            self.skipTest("TAXONOMY.json not reachable in this checkout")
        tax = json.loads(tax_path.read_text(encoding="utf-8"))
        tax_ids = {row["impact_id"] for row in tax}
        m = _MOD.IMPACT_METHODOLOGY_TO_CHECK31
        self.assertEqual(
            set(m),
            tax_ids,
            "IMPACT_METHODOLOGY_TO_CHECK31 keys diverge from TAXONOMY.json "
            "impact_ids -- update the reconciliation constant",
        )
        # Each mapped tier must be the leading word of that row's
        # severity_ceiling (the documented derivation rule).
        for row in tax:
            tier, _hint = m[row["impact_id"]]
            ceiling = row["severity_ceiling"]
            self.assertTrue(
                ceiling.startswith(tier),
                f"{row['impact_id']}: mapped tier {tier!r} is not the leading "
                f"tier of severity_ceiling {ceiling!r}",
            )


class MethodologyMappingDriftGateTests(unittest.TestCase):
    """G9 -- IMPACT_METHODOLOGY_TO_CHECK31 drift gate (fail-closed completeness).

    Non-vacuous: the gate must FAIL when a corpus ``impact_id`` has no map
    entry (the silent-fork class GAP_REPORT G9 names), and PASS only when the
    map covers every corpus playbook. Tests build synthetic corpus YAMLs so
    they do not depend on the live corpus being present.
    """

    def _write_corpus(self, dir_path: Path, impact_ids):
        corpus_dir = dir_path / "audit" / "corpus_tags"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        lines = [
            "schema: auditooor.impact_hunting_methodology.v1",
            "version: 1",
            "playbooks:",
        ]
        for iid in impact_ids:
            lines.append(f"- impact_id: {iid}")
            lines.append(f"  title: synthetic playbook for {iid}")
        path = corpus_dir / "impact_hunting_methodology.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_parser_extracts_only_impact_id_slugs(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_corpus(Path(td), ["direct-theft-funds", "reentrancy"])
            ids = _MOD.impact_ids_from_methodology_yaml(path)
            self.assertEqual(ids, {"direct-theft-funds", "reentrancy"})

    def test_parser_ignores_quoted_and_nested_noise(self):
        # impact_id values can appear quoted; title/other lines must not match.
        with tempfile.TemporaryDirectory() as td:
            corpus_dir = Path(td) / "audit" / "corpus_tags"
            corpus_dir.mkdir(parents=True)
            path = corpus_dir / "impact_hunting_methodology.yaml"
            path.write_text(
                "playbooks:\n"
                "- impact_id: 'oracle-manipulation'\n"
                "  title: not an impact_id line\n"
                "  notes: impact_id appears in prose here, must be ignored\n"
                '- impact_id: "chain-halt-shutdown"\n',
                encoding="utf-8",
            )
            ids = _MOD.impact_ids_from_methodology_yaml(path)
            self.assertEqual(ids, {"oracle-manipulation", "chain-halt-shutdown"})

    def test_drift_detected_when_new_playbook_unmapped(self):
        # A 33rd playbook (not in the map) is exactly the silent-fork the gate
        # must catch.
        with tempfile.TemporaryDirectory() as td:
            ids = list(_MOD.IMPACT_METHODOLOGY_TO_CHECK31) + ["brand-new-impact-class"]
            path = self._write_corpus(Path(td), ids)
            missing = _MOD.check_methodology_mapping_drift(path)
            self.assertIn("brand-new-impact-class", missing)
            self.assertEqual(missing, {"brand-new-impact-class"})

    def test_no_drift_when_map_covers_corpus(self):
        with tempfile.TemporaryDirectory() as td:
            ids = list(_MOD.IMPACT_METHODOLOGY_TO_CHECK31)
            path = self._write_corpus(Path(td), ids)
            self.assertEqual(_MOD.check_methodology_mapping_drift(path), set())

    def test_map_entry_without_corpus_playbook_is_tolerated(self):
        # One-directional gate: a map entry not in the corpus is allowed (it
        # may pre-stage a forthcoming playbook). Only corpus -> map drift fails.
        with tempfile.TemporaryDirectory() as td:
            ids = [k for k in _MOD.IMPACT_METHODOLOGY_TO_CHECK31][:5]
            path = self._write_corpus(Path(td), ids)
            self.assertEqual(_MOD.check_methodology_mapping_drift(path), set())

    def test_find_methodology_yaml_walks_up(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_corpus(root, ["direct-theft-funds"])
            nested = root / "tools" / "sub" / "deep"
            nested.mkdir(parents=True)
            found = _MOD.find_methodology_yaml(nested)
            self.assertIsNotNone(found)
            self.assertEqual(
                found.resolve(),
                (root / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml").resolve(),
            )

    def test_find_methodology_yaml_returns_none_when_absent(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(_MOD.find_methodology_yaml(Path(td)))

    def test_live_corpus_is_fully_mapped_when_reachable(self):
        # The whole point of G9: against the ACTUAL committed corpus, the map
        # must have zero drift. Skip cleanly if the corpus is not in this
        # checkout (the gate is repo-portable).
        path = _MOD.find_methodology_yaml()
        if path is None:
            self.skipTest("impact_hunting_methodology.yaml not reachable in this checkout")
        missing = _MOD.check_methodology_mapping_drift(path)
        self.assertEqual(
            missing,
            set(),
            "IMPACT_METHODOLOGY_TO_CHECK31 is missing live-corpus impact_id(s): "
            f"{sorted(missing)} -- map each new playbook to (tier, rubric_row_hint)",
        )

    def test_cli_drift_flag_passes_on_synthetic_covered_corpus(self):
        # rc=0 path through main() with the CLI flag.
        with tempfile.TemporaryDirectory() as td:
            ids = list(_MOD.IMPACT_METHODOLOGY_TO_CHECK31)
            self._write_corpus(Path(td), ids)
            # Patch find_methodology_yaml to point at the synthetic corpus by
            # invoking the runner indirectly: simplest is to chdir-free call
            # _run_methodology_drift_gate after monkeypatching the finder.
            orig = _MOD.find_methodology_yaml
            _MOD.find_methodology_yaml = lambda start=None: (
                Path(td) / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
            )
            try:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = _MOD.main(["--check-methodology-drift", "--json"])
                self.assertEqual(rc, 0, buf.getvalue())
                payload = json.loads(buf.getvalue())
                self.assertEqual(payload["missing_from_map"], [])
                self.assertEqual(payload["rc"], 0)
            finally:
                _MOD.find_methodology_yaml = orig

    def test_cli_drift_flag_fails_on_synthetic_drifted_corpus(self):
        # rc=1 path: an unmapped playbook makes the gate fail closed.
        with tempfile.TemporaryDirectory() as td:
            ids = list(_MOD.IMPACT_METHODOLOGY_TO_CHECK31) + ["unmapped-future-class"]
            self._write_corpus(Path(td), ids)
            orig = _MOD.find_methodology_yaml
            _MOD.find_methodology_yaml = lambda start=None: (
                Path(td) / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
            )
            try:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = _MOD.main(["--check-methodology-drift", "--json"])
                self.assertEqual(rc, 1, buf.getvalue())
                payload = json.loads(buf.getvalue())
                self.assertIn("unmapped-future-class", payload["missing_from_map"])
            finally:
                _MOD.find_methodology_yaml = orig

    def test_cli_drift_flag_advisory_when_corpus_absent(self):
        # rc=2 advisory when the corpus is not present.
        orig = _MOD.find_methodology_yaml
        _MOD.find_methodology_yaml = lambda start=None: None
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = _MOD.main(["--check-methodology-drift", "--json"])
            self.assertEqual(rc, 2, buf.getvalue())
            payload = json.loads(buf.getvalue())
            self.assertFalse(payload["corpus_found"])
        finally:
            _MOD.find_methodology_yaml = orig


# ---------------------------------------------------------------------------
# Per-row Severity-column rubric (Immunefi Scope-A/B shape, e.g. Obyte).
#
# Regression + feature coverage for the additive branch in
# ``_parse_rubric_tiers`` that reads the tier from each ROW's own ``Severity``
# cell (under a non-tier ``## Scope A/B`` heading) and explodes ``<br>``-packed,
# bullet-per-line impact cells into individual grounding sentences. Before this
# branch existed these rows were silently dropped (no ``## Critical`` heading is
# ever seen), so every selected_impact failed BC1 rubric grounding.
# ---------------------------------------------------------------------------

# Mirrors the real /Users/wolf/audits/obyte/SEVERITY.md shape: one table per
# scope, tier carried per row in a `Severity` column, multi-impact cells joined
# by `<br>` with a leading `- ` bullet on each sentence.
_OBYTE_SEVERITY_MD = """\
# Obyte -- Immunefi Severity Rubric (per-row Severity column, test fixture)

## Scope A - Blockchain / DLT (ocore)
| Severity | Reward | In-scope impact rows |
|----------|--------|----------------------|
| Critical | Max $50,000 | - Network permanently unable to confirm new transactions (total network shutdown)<br>- Direct loss of funds<br>- Permanent freezing of funds (fix requires hardfork) |
| High     | Flat $1,700 | Temporary freezing of network transactions by delaying adequate processing for at least 1 DAY |
| Medium   | Flat $1,000 | Temporary freezing of network transactions by delaying adequate processing for at least 1 HOUR |

## Scope B - Smart Contract (Autonomous Agents)
| Severity | Reward | In-scope impact rows |
|----------|--------|----------------------|
| Critical | Flat $2,500 | - Direct theft of any user funds, at-rest or in-motion, OTHER than unclaimed yield<br>- Protocol insolvency |
| Medium   | Flat $1,000 | - Temporary freezing of funds<br>- Smart contract unable to operate due to lack of token funds |
"""


class PerRowSeverityColumnRubric(unittest.TestCase):
    """Obyte-style per-row `Severity` column parsing + end-to-end grounding."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _write_workspace(self.ws, _OBYTE_SEVERITY_MD)
        (self.ws / "poc").mkdir(exist_ok=True)
        (self.ws / "poc" / "synth_proof.txt").write_text("synthetic proof\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # --- unit: parser resolves row -> its own Severity cell --------------

    def test_parse_rubric_tiers_reads_per_row_severity(self):
        tiers = _MOD._parse_rubric_tiers(_OBYTE_SEVERITY_MD)
        # <br>-packed Scope A Critical cell exploded into 3 sentences.
        self.assertIn("Direct loss of funds", tiers["Critical"])
        self.assertIn(
            "Network permanently unable to confirm new transactions (total network shutdown)",
            tiers["Critical"],
        )
        # Scope B Critical rows are also collected (second scope table).
        self.assertIn("Protocol insolvency", tiers["Critical"])
        # High/Medium rows land under their own row-severity, not Critical.
        self.assertIn(
            "Temporary freezing of network transactions by delaying adequate processing for at least 1 DAY",
            tiers["High"],
        )
        self.assertIn("Temporary freezing of funds", tiers["Medium"])
        self.assertNotIn("Direct loss of funds", tiers["High"])
        self.assertNotIn("Direct loss of funds", tiers["Medium"])

    def test_split_multi_impact_cell_explodes_br_bullets(self):
        cell = "- Direct loss of funds<br>- Permanent freezing of funds (fix requires hardfork)"
        self.assertEqual(
            _MOD._split_multi_impact_cell(cell),
            ["Direct loss of funds", "Permanent freezing of funds (fix requires hardfork)"],
        )
        # Case-insensitive <br/> variant, single plain sentence still returned.
        self.assertEqual(_MOD._split_multi_impact_cell("A<BR/>B"), ["A", "B"])
        self.assertEqual(_MOD._split_multi_impact_cell("plain sentence"), ["plain sentence"])
        self.assertEqual(_MOD._split_multi_impact_cell(""), [])

    # --- end-to-end: a draft grounds against a per-row-severity row ------

    def test_critical_impact_from_br_cell_grounds_and_passes(self):
        block = """## Program Impact Mapping

- program: Obyte
- asset: ocore
- selected_impact: Direct loss of funds
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "obyte_crit.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)
        self.assertIn("[PASS/REQ]", out)

    def test_high_row_impact_grounds_and_passes(self):
        block = """## Program Impact Mapping

- program: Obyte
- asset: ocore
- selected_impact: Temporary freezing of network transactions by delaying adequate processing for at least 1 DAY
- severity_implied: High
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "obyte_high.md", _draft_with_severity("High", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 0, out)

    def test_row_severity_is_authoritative_tier_crossing_fails(self):
        # Selecting a HIGH-row impact but claiming Critical must FAIL BC2:
        # proves the tier is bound to the ROW's Severity cell, not merely that
        # the text appears somewhere in the rubric.
        block = """## Program Impact Mapping

- program: Obyte
- asset: ocore
- selected_impact: Temporary freezing of network transactions by delaying adequate processing for at least 1 DAY
- severity_implied: Critical
- proof_artifact: poc/synth_proof.txt
- not_proven_impacts: []
"""
        d = _write_draft(self.ws, "obyte_cross.md", _draft_with_severity("Critical", block))
        rc, out = _run(["--draft", str(d)])
        self.assertEqual(rc, 1, out)
        self.assertIn("tier mismatch", out)


if __name__ == "__main__":
    unittest.main()
