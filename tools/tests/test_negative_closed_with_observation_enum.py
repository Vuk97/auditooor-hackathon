#!/usr/bin/env python3
# r36-rebuttal: lane-ENUM-FIX-NEGATIVE-CLOSED-WITH-OBSERVATION registered via tools/agent-pathspec-register.py
"""Gap #48 - lane-output-category enum extension tests.

Verifies that `NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE`
(codified 2026-05-26) is wired through every enum location:

1. tools/salvage-negation-verdict-check.py NEGATION_TOKENS list contains
   the new token AND a verdict using it + the other two framing
   elements (negation evidence + flip clause) passes the Gap #37b gate.
2. tools/salvage-negation-verdict-check.py recognizes the new token
   alone (without complete framing) and treats it identically to the
   other negation tokens (token-present + missing-evidence path yields
   fail-no-negation-evidence-list, NOT fail-no-negation-token).
3. tools/exhaustion-verdict-tools-attempt-required-check.py
   EXHAUSTION_TRIGGERS list contains a phrase matching the new token
   so the Gap #37 depth-tool-attempt gate fires on the new verdict.
4. docs/HACKER_LANE_BRIEF_TEMPLATE.md verdict-enum block contains the
   new token literal AND the observation-block shape.
5. tools/lane-brief-template.sh emit_reply_section contains the new
   token literal.
6. tools/pre-submit-check.sh Check #111 remediation block surfaces the
   new token literal.
7. Schema version of the salvage-negation gate is unchanged (this is a
   pure enum addition; no breaking change).

Empirical anchor: HUNT-SMT-1 (2026-05-26) CHECK-7
`Bytes.reverse(bytes memory)` empty-input underflow at
`src/solidity-merkle-trees/src/trie/Bytes.sol:226`, symmetric to
staged `smt-library-latent-defects-LOW` Defect A.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SALVAGE_TOOL = _REPO_ROOT / "tools" / "salvage-negation-verdict-check.py"
_EXHAUSTION_TOOL = _REPO_ROOT / "tools" / "exhaustion-verdict-tools-attempt-required-check.py"
_BRIEF_TEMPLATE_MD = _REPO_ROOT / "docs" / "HACKER_LANE_BRIEF_TEMPLATE.md"
_BRIEF_TEMPLATE_SH = _REPO_ROOT / "tools" / "lane-brief-template.sh"
_PRE_SUBMIT_CHECK = _REPO_ROOT / "tools" / "pre-submit-check.sh"

NEW_TOKEN = "NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE"
NEW_TRIGGER_PHRASE = "negative-closed-with-observation"


def _import_tool(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader, f"could not load {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SALVAGE = _import_tool(_SALVAGE_TOOL, "salvage_negation_verdict_check_enumtest")
EXHAUSTION = _import_tool(_EXHAUSTION_TOOL, "exhaustion_verdict_check_enumtest")


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _in_scope_lane_path(root: Path) -> Path:
    p = root / "reports" / "v3_iter_2026-05-26_enumfix" / "lane_TEST" / "results.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _complete_framing_with_new_token() -> str:
    return (
        "# Lane results\n\n"
        "## Verdict\n\n"
        f"{NEW_TOKEN} after HUNT-SMT-1 closed the surface; one\n"
        "incremental observation logged below for fold-in to the existing\n"
        "smt-library-latent-defects-LOW bundle (pending operator authorization).\n\n"
        "observation:\n"
        "  finding_class: empty-input-underflow\n"
        "  symmetric_to: smt-library-latent-defects-LOW (Defect A)\n"
        "  file_line: src/solidity-merkle-trees/src/trie/Bytes.sol:226\n"
        "  reachability: 0 in-tree callers (R60 unreachable)\n"
        "  fold_in_candidate: yes / pending-operator-authorization\n"
        "  L34_v2_status: NEW_DRAFT_NOT_STAGED / FOLD_IN_PENDING_OP_AUTH\n\n"
        "## Negation evidence\n\n"
        "- Halmos: timeout at depth 7 after 30 min\n"
        "- Foundry 1M fuzz: 0 counterexamples in 1,000,000 runs\n"
        "- Differential vs reference impl: bit-equal across 50K inputs\n\n"
        "## What would flip this\n\n"
        "A new caller of `Bytes.reverse(bytes memory)` with attacker-controlled\n"
        "empty input would re-open the verdict. Specifically, any new code path\n"
        "in `src/solidity-merkle-trees/src/trie/` that invokes the empty-input\n"
        "branch invalidates the negation.\n"
    )


# ---------------------------------------------------------------------------
# Case 1: salvage-negation tokens list contains the new token.
# ---------------------------------------------------------------------------
class TestSalvageNegationTokenListContainsNewToken(unittest.TestCase):
    def test_new_token_present_in_negation_tokens(self):
        self.assertIn(
            NEW_TOKEN,
            SALVAGE.NEGATION_TOKENS,
            f"{NEW_TOKEN} must be in SALVAGE.NEGATION_TOKENS so Gap #37b "
            "(Check #111) accepts it as a complete negation framing token.",
        )

    def test_new_token_matched_before_negative_closed_substring(self):
        # The detector iterates in list order; the more-specific token
        # must come BEFORE the bare "NEGATIVE-CLOSED" substring so it
        # wins when both could match.
        idx_specific = SALVAGE.NEGATION_TOKENS.index(NEW_TOKEN)
        idx_bare = SALVAGE.NEGATION_TOKENS.index("NEGATIVE-CLOSED")
        self.assertLess(
            idx_specific,
            idx_bare,
            "NEW_TOKEN must precede NEGATIVE-CLOSED in NEGATION_TOKENS so "
            "the more-specific form wins detection",
        )


# ---------------------------------------------------------------------------
# Case 2: complete-framing verdict using the new token passes the gate.
# ---------------------------------------------------------------------------
class TestSalvageNegationCompleteFramingPasses(unittest.TestCase):
    def test_full_framing_with_new_token_passes(self):
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        _write(p, _complete_framing_with_new_token())
        r = SALVAGE.evaluate(p, strict=False)
        self.assertEqual(r["verdict"], SALVAGE.V_PASS_COMPLETE)
        self.assertEqual(r["evidence"]["negation_token"], NEW_TOKEN)
        self.assertGreaterEqual(
            r["evidence"]["negation_evidence_row_count"], 3
        )
        self.assertTrue(r["evidence"]["has_flip_clause"])

    def test_new_token_alone_recognised_as_token_not_missing(self):
        # Token present but evidence + flip missing => fail-no-negation-
        # evidence-list (NOT fail-no-negation-token). This proves the new
        # token is in the recognised set; the remaining-framing failures
        # are independent.
        tmp = Path(tempfile.mkdtemp())
        p = _in_scope_lane_path(tmp)
        _write(
            p,
            "## Verdict\n\n"
            f"{NEW_TOKEN}. Lane closed; observation logged.\n",
        )
        r = SALVAGE.evaluate(p, strict=False)
        # The verdict-language trigger "salvage" / "drop" / "exhausted" /
        # etc. needs to be present in the prose; the new token alone
        # without one of those triggers would route to pass-no-verdict-
        # language. So we add an explicit verdict trigger word.
        _write(
            p,
            "## Verdict\n\n"
            f"{NEW_TOKEN}. Lane closed; observation logged. The candidate is\n"
            "exhausted as a standalone draft; only fold-in remains.\n",
        )
        r = SALVAGE.evaluate(p, strict=False)
        # Now should fail at the evidence-list step, not at the token
        # step. This proves the token IS recognised.
        self.assertEqual(r["verdict"], SALVAGE.V_FAIL_NO_EVIDENCE)
        self.assertEqual(r["evidence"]["negation_token"], NEW_TOKEN)


# ---------------------------------------------------------------------------
# Case 3: exhaustion-gate trigger list contains the new phrase.
# ---------------------------------------------------------------------------
class TestExhaustionTriggerListContainsNewPhrase(unittest.TestCase):
    def test_new_phrase_present_in_exhaustion_triggers(self):
        self.assertIn(
            NEW_TRIGGER_PHRASE,
            EXHAUSTION.EXHAUSTION_TRIGGERS,
            f"{NEW_TRIGGER_PHRASE!r} must be in "
            "EXHAUSTION.EXHAUSTION_TRIGGERS so Gap #37 (Check #109) "
            "treats the new verdict as exhaustion-class.",
        )

    def test_new_token_lane_triggers_exhaustion_gate(self):
        # A lane file containing the new token (lower-cased it's the
        # NEW_TRIGGER_PHRASE prefix) must trigger the Gap #37 gate.
        tmp = Path(tempfile.mkdtemp())
        lane = tmp / "lane.md"
        _write(
            lane,
            "## Verdict\n\n"
            f"{NEW_TOKEN} after exhaustive SMT-DRILL re-validation.\n",
        )
        log = tmp / ".auditooor" / "depth_tools_log.jsonl"
        result = EXHAUSTION.evaluate(lane, tmp, log, strict=False)
        # Empty log + exhaustion-class verdict => fail-incomplete (the
        # gate fires).
        self.assertEqual(result["verdict"], EXHAUSTION.V_FAIL_INCOMPLETE)
        self.assertIn("negative-closed-with-observation", result["evidence"]["trigger_excerpt"].lower())


# ---------------------------------------------------------------------------
# Case 4: canonical brief template doc carries the new enum.
# ---------------------------------------------------------------------------
class TestBriefTemplateMdHasNewEnum(unittest.TestCase):
    def test_new_token_in_brief_template_md(self):
        text = _BRIEF_TEMPLATE_MD.read_text(encoding="utf-8")
        self.assertIn(
            NEW_TOKEN,
            text,
            f"{NEW_TOKEN} must appear in docs/HACKER_LANE_BRIEF_TEMPLATE.md "
            "verdict enum so spawned lanes know the option exists.",
        )

    def test_observation_block_shape_in_brief_template_md(self):
        text = _BRIEF_TEMPLATE_MD.read_text(encoding="utf-8")
        # Spot-check the observation block keys.
        for key in (
            "finding_class:",
            "symmetric_to:",
            "file_line:",
            "reachability:",
            "fold_in_candidate:",
            "L34_v2_status:",
        ):
            self.assertIn(
                key,
                text,
                f"observation-block key {key!r} missing from brief template.",
            )


# ---------------------------------------------------------------------------
# Case 5: lane-brief-template.sh emit_reply_section carries the new token.
# ---------------------------------------------------------------------------
class TestLaneBriefShellTemplateHasNewToken(unittest.TestCase):
    def test_new_token_in_lane_brief_template_sh(self):
        text = _BRIEF_TEMPLATE_SH.read_text(encoding="utf-8")
        self.assertIn(
            NEW_TOKEN,
            text,
            f"{NEW_TOKEN} must appear in tools/lane-brief-template.sh "
            "emit_reply_section so generated briefs surface the option.",
        )


# ---------------------------------------------------------------------------
# Case 6: pre-submit-check.sh Check #111 remediation surfaces the new token.
# ---------------------------------------------------------------------------
class TestPreSubmitCheckRemediationHasNewToken(unittest.TestCase):
    def test_new_token_in_pre_submit_check_remediation(self):
        text = _PRE_SUBMIT_CHECK.read_text(encoding="utf-8")
        self.assertIn(
            NEW_TOKEN,
            text,
            f"{NEW_TOKEN} must appear in pre-submit-check.sh remediation "
            "messaging so authors of failing drafts see the option.",
        )


# ---------------------------------------------------------------------------
# Case 7: schema version unchanged - this is a pure enum addition.
# ---------------------------------------------------------------------------
class TestSchemaVersionUnchanged(unittest.TestCase):
    def test_salvage_schema_still_v1(self):
        self.assertEqual(
            SALVAGE.SCHEMA_VERSION,
            "auditooor.gap37b_salvage_negation_verdict.v1",
            "Schema bump should not be needed for a pure enum addition; "
            "if it is bumped, update this test AND all downstream "
            "consumers (lane-integrator, etc.).",
        )

    def test_exhaustion_schema_still_v1(self):
        self.assertEqual(
            EXHAUSTION.SCHEMA_VERSION,
            "auditooor.gap37_exhaustion_verdict_tools_attempt.v1",
            "Schema bump should not be needed for a pure enum addition.",
        )


if __name__ == "__main__":
    unittest.main()
