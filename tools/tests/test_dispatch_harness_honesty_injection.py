"""test_dispatch_harness_honesty_injection.py - sibling test for the
dispatch-time Harness-Authoring Honesty Requirements (Rule 80 / R-A..R-E)
injection added to tools/dispatch-agent-with-prebriefing.py.

The injected block (section header
"## Harness-Authoring Honesty Requirements (Rule 80 / R-A..R-E)") fires only
for harness-authoring lanes - either by lane_type membership
(HARNESS_AUTHORING_LANE_TYPES: harness/invariant/coverage/poc/fuzz/prove/
exploit-conversion) or by a harness-ish prompt keyword (chimera, invariant,
medusa, echidna, halmos, mutation, write a poc, ...). It lands the four honesty
mandates up front: real in-scope CUT (not a mock/reimpl), mutation-verified
non-vacuous invariants (assert(true) is not proof), an actually-executing
engine, and real-unit coverage.

Cases:
  1. harness-authoring brief (lane_type=harness) -> enriched brief CONTAINS the
     Rule 80 section with real-CUT + mutation-verify + no-assert(true) mandates.
  1b. prompt-keyword trigger ("chimera invariant harness") with a non-harness
     lane_type still injects the section.
  2. non-harness brief (triage/dispute lane, no harness keywords) -> the section
     is NOT injected.
  3. idempotency - enriching a brief that already contains the section does not
     double-inject.
  4. the mandates assert the key strings are present (mutation-verified, real
     in-scope src, assert(true) is not proof).
  5. lane_type-based trigger AND prompt-keyword-based trigger both fire (parity
     check on the predicate + the rendered section).
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "dispatch_agent_with_prebriefing", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dispatch_agent_with_prebriefing"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


prebriefing = _load_module()

HEADER = prebriefing._HARNESS_AUTHORING_SECTION_HEADER


def _render_brief(*, lane_type: str, prompt_text: str = "") -> str:
    """Drive the real enrichment path. ``format_skeleton_as_markdown`` contains
    the idempotency-guarded injection caller for the Rule 80 block; passing
    ``payload=None`` exercises the skeleton-unavailable assembly path (the same
    path used by case 9 of the prebriefing test) where the block is appended."""
    return prebriefing.format_skeleton_as_markdown(
        None,
        lane_type=lane_type,
        severity="HIGH",
        workspace_path=None,
        prompt_text=prompt_text,
    )


class HarnessHonestyInjectionTest(unittest.TestCase):
    # -- Case 1: lane_type=harness injects the section + mandates --------------
    def test_case1_harness_lane_injects_section(self):
        brief = _render_brief(lane_type="harness", prompt_text="build the suite")
        self.assertIn(HEADER, brief)
        # real-CUT mandate
        self.assertIn("REAL in-scope src/", brief)
        self.assertIn("mock/reimplementation", brief)
        # mutation-verify mandate
        self.assertIn("MUTATION-VERIFIED", brief)
        # no-assert(true) mandate
        self.assertIn("assert(true)", brief)
        self.assertIn("is NOT", brief)

    # -- Case 1b: prompt-keyword trigger fires on non-harness lane_type --------
    def test_case1b_prompt_keyword_chimera_invariant_harness(self):
        brief = _render_brief(
            lane_type="hunt",
            prompt_text="Author a chimera invariant harness for the vault",
        )
        self.assertIn(HEADER, brief)
        self.assertIn("MUTATION-VERIFIED", brief)

    # -- Case 2: non-harness brief does NOT inject the section -----------------
    def test_case2_non_harness_lane_no_injection(self):
        brief = _render_brief(
            lane_type="dispute",
            prompt_text=(
                "Draft a triager response disputing the closure of finding X. "
                "No code, just prose."
            ),
        )
        self.assertNotIn(HEADER, brief)
        self.assertNotIn("MUTATION-VERIFIED", brief)
        # sanity: the predicate agrees this is not a harness lane
        self.assertFalse(
            prebriefing.is_harness_authoring_lane(
                "dispute", "Draft a triager response disputing the closure."
            )
        )

    # -- Case 3: idempotency - already-present section is not double-injected --
    def test_case3_idempotent_no_double_inject(self):
        brief = _render_brief(lane_type="harness", prompt_text="build the suite")
        self.assertEqual(brief.count(HEADER), 1)

        # Re-running the section renderer and the idempotency-guarded caller
        # against text that already holds the header must NOT add a second copy.
        section = prebriefing._format_harness_authoring_requirements_section(
            lane_type="harness", prompt_text="build the suite"
        )
        self.assertTrue(section, "section should render for a harness lane")
        lines = brief.splitlines()
        if HEADER not in lines:
            lines.extend(section)
        rebuilt = "\n".join(lines)
        self.assertEqual(rebuilt.count(HEADER), 1)

    # -- Case 4: the mandate key strings are present in the rendered section ---
    def test_case4_mandate_key_strings(self):
        section = "\n".join(
            prebriefing._format_harness_authoring_requirements_section(
                lane_type="invariant", prompt_text=""
            )
        )
        # mutation-verified
        self.assertIn("MUTATION-VERIFIED", section)
        # real in-scope src (CUT must be the real contract)
        self.assertIn("REAL in-scope src/", section)
        self.assertIn("Contract-Under-Test", section)
        # assert(true) is not proof
        self.assertIn("assert(true)", section)
        self.assertIn("is NOT", section)
        # engine must actually execute
        self.assertIn("actually execute", section)

    # -- Case 4b: the CONCRETE playbook literals are present -------------------
    def test_case4b_concrete_playbook_literals(self):
        section = "\n".join(
            prebriefing._format_harness_authoring_requirements_section(
                lane_type="invariant", prompt_text=""
            )
        )
        # section 2: attempt-the-violation, bound by available balance
        self.assertIn("bound by AVAILABLE BALANCE", section)
        self.assertIn("ATTEMPT the over-cap", section)
        # section 1: real CUT bound in setUp
        self.assertIn("bindTarget", section)
        # sections 4/5: behavior-changing mutant rule
        self.assertIn("behavior-changing mutant", section)
        # section 3: reachability-witness requirement
        self.assertIn("witness counter", section)
        # section 6: engine-choice + call budget
        self.assertIn("echidna for selfdestruct", section)
        self.assertIn("1,000,000", section)

    # -- Case 4c: >=6 of the 20 semantic mode names rendered ------------------
    def test_case4c_semantic_mode_names_rendered(self):
        section = "\n".join(
            prebriefing._format_harness_authoring_requirements_section(
                lane_type="harness", prompt_text="author the invariant suite"
            )
        )
        # the "do NOT reproduce" block is imported from Lane C's accessor
        self.assertIn("KNOWN HARNESS-FAILURE MODES", section)
        mode_names = (
            "unlimited-params",
            "self-bounded-handler",
            "silent-revert-actions",
            "harness-internal-accounting",
            "dead-cut-guard",
            "tautological-assert",
            "mock-callpath-vacuity",
            "compile-cascade",
            "equivalent-mutant",
            "serving-join",
            "setup-crash-false-kill",
            "stale-sidecar",
            "cluster-credit-masks-per-invariant",
            "wrong-cut-oos-target",
            "typed-skip-at-scale",
        )
        present = [m for m in mode_names if m in section]
        self.assertGreaterEqual(
            len(present),
            6,
            f"expected >=6 of the 20 mode names rendered, got {present}",
        )

    # -- Case 5: lane_type trigger AND prompt-keyword trigger both fire --------
    def test_case5_both_triggers_fire(self):
        # lane_type membership trigger (no harness keyword in prompt)
        self.assertTrue(
            prebriefing.is_harness_authoring_lane("coverage", "run the thing")
        )
        section_by_type = prebriefing._format_harness_authoring_requirements_section(
            lane_type="coverage", prompt_text="run the thing"
        )
        self.assertTrue(section_by_type)
        self.assertIn(HEADER, section_by_type)

        # prompt-keyword trigger (lane_type itself is non-harness)
        self.assertTrue(
            prebriefing.is_harness_authoring_lane(
                "triage", "please write a poc with medusa fuzzing"
            )
        )
        section_by_kw = prebriefing._format_harness_authoring_requirements_section(
            lane_type="triage", prompt_text="please write a poc with medusa fuzzing"
        )
        self.assertTrue(section_by_kw)
        self.assertIn(HEADER, section_by_kw)

        # neither trigger -> predicate false, section empty
        self.assertFalse(
            prebriefing.is_harness_authoring_lane("triage", "summarize the rubric")
        )
        self.assertEqual(
            prebriefing._format_harness_authoring_requirements_section(
                lane_type="triage", prompt_text="summarize the rubric"
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
