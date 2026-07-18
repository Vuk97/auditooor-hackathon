"""test_hunt_brief_completeness_check.py - PR9a-1 hunt-brief completeness gate.

Covers the standalone worker tool (tools/hunt-brief-completeness-check.py)
and its fail-closed wiring into the dispatch path
(tools/dispatch-agent-with-prebriefing.py).

Worker-tool cases:
  1. Complete hunt brief (all five pillars) -> pass-complete (rc=0).
  2. Brief missing the MCP-first block -> fail-no-mcp-first-block (rc=1).
  3. Brief missing one of the three required MCP callables ->
     fail-no-mcp-first-block.
  4. Brief missing hunt-definition/skip-set -> fail-no-hunt-definition-skip-set.
  5. Brief missing capability-adoption -> fail-no-capability-adoption.
  5b. Capability-adoption isolated (brain-prime via callable, no hacker-q).
  6. Non-hunt lane -> pass-not-hunt-lane (gate does not apply).
  7. Valid pr9a-rebuttal overrides a fail -> ok-rebuttal.
  8. Empty / oversized rebuttal is ignored; original fail stands.
  9. missing_pillars lists every missing pillar; verdict reports first (a->e).
 10. CLI end-to-end smoke (--prompt-file + --lane-type + --json).
 11. Exit codes map correctly per verdict (including new fail verdicts).
 19. Brief missing Defense Surface section -> fail-no-defense-surface-section.
 20. Brief missing Full-Audit Results section -> fail-no-full-audit-results-section.
 21. Brief with "(none found)" defense surface still satisfies pillar (d).
 22. Defense-surface pillar is independent of other pillars.
 23. Full-audit-results pillar is independent of other pillars.
 24. Filing lane is unaffected by new pillars (pass-not-hunt-lane).
 25. missing_pillars includes all five when brief is empty.
 26. Dispatch-route: enriched brief (containing 15r + 15s) passes gate.

Dispatch-wiring cases:
 12. run_hunt_brief_completeness_check: non-hunt lane -> not-hunt-lane.
 13. run_hunt_brief_completeness_check: disabled via env -> disabled.
 14. run_hunt_brief_completeness_check: complete brief -> pass-complete.
 15. main(--dispatch) with incomplete hunt brief refuses (rc=4), no claude.
 16. main(--dispatch) with complete hunt brief proceeds.
 17. main(--dispatch) warn-only env downgrades a fail to dispatch.
 18. main(--dispatch) non-hunt lane is never blocked by this gate.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Dict, Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hunt-brief-completeness-check.py"
DISPATCH_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


hbc = _load("hunt_brief_completeness_check", TOOL_PATH)
prebriefing = _load("dispatch_agent_with_prebriefing", DISPATCH_PATH)


COMPLETE_BRIEF = """\
## MCP-FIRST RECALL (your first action)
Call vault_resume_context, vault_brain_prime_context, and
vault_known_dead_ends before any source read.

## DEDUP-FIRST + canonical hunt definition
A hunt is the FULL pipeline (dedup-first + deep clone + mining). FIRST consult
hunt_skip_set.json and SKIP anything filed/killed/dead-ended.

## Capability adoption (ADD-D)
Consume the brain-prime context and traverse the per-function hacker-questions
(vault_per_function_hunter_brief) against each target function.

## Section 15r - Defense Surface (traverse/bypass these)

_Present guards/modifiers in the audit-pin tree. These are the defense-in-depth
layers an attack must traverse or bypass._

- No present guards extracted from in-scope source.

## Section 15s - Full-Audit Results (what the audit already found)

_The pipeline already ran detectors, deep engines, and built the exploit queue._

- No prior audit artifacts found for this workspace.

## TASK
Hunt for bugs.
"""


def _drop(text: str, marker: str) -> str:
    """Remove a single token/phrase from the brief (case-insensitive line del)."""
    out = []
    for line in text.splitlines():
        if marker.lower() in line.lower():
            continue
        out.append(line)
    return "\n".join(out) + "\n"


class WorkerToolTests(unittest.TestCase):
    def test_01_complete_brief_passes(self):
        r = hbc.evaluate_brief(COMPLETE_BRIEF, lane_type="hunt")
        self.assertEqual(r["verdict"], "pass-complete")
        self.assertEqual(r["missing_pillars"], [])

    def test_02_missing_mcp_block(self):
        # Remove the MCP-first header AND callables.
        brief = _drop(COMPLETE_BRIEF, "MCP-FIRST")
        brief = _drop(brief, "vault_resume_context")
        brief = _drop(brief, "vault_brain_prime_context")
        brief = _drop(brief, "vault_known_dead_ends")
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertEqual(r["verdict"], "fail-no-mcp-first-block")
        self.assertIn("mcp-first-block", r["missing_pillars"])

    def test_03_missing_one_required_callable(self):
        brief = _drop(COMPLETE_BRIEF, "vault_known_dead_ends")
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertEqual(r["verdict"], "fail-no-mcp-first-block")
        self.assertIn(
            "vault_known_dead_ends",
            r["pillar_evidence"]["mcp_first"]["missing_required_callables"],
        )

    def test_04_missing_hunt_definition_skip_set(self):
        brief = _drop(COMPLETE_BRIEF, "FULL pipeline")
        brief = _drop(brief, "hunt_skip_set.json")
        brief = _drop(brief, "DEDUP-FIRST")
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertEqual(r["verdict"], "fail-no-hunt-definition-skip-set")
        self.assertIn("hunt-definition-skip-set", r["missing_pillars"])

    def test_05_missing_capability_adoption(self):
        brief = _drop(COMPLETE_BRIEF, "brain-prime")
        brief = _drop(brief, "vault_brain_prime_context")
        brief = _drop(brief, "hacker-question")
        brief = _drop(brief, "vault_per_function_hunter_brief")
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        # Removing vault_brain_prime_context also breaks pillar (a); verdict
        # reports the FIRST missing pillar (a) but capability-adoption is
        # still flagged in missing_pillars.
        self.assertIn("capability-adoption", r["missing_pillars"])

    def test_05b_capability_adoption_isolated(self):
        # Keep MCP block + hunt-def + 15r + 15s intact; drop ONLY capability
        # signals that are not also MCP-first callables.
        brief = (
            "## MCP-FIRST RECALL\n"
            "vault_resume_context vault_brain_prime_context "
            "vault_known_dead_ends\n"
            "A hunt is the FULL pipeline; consult hunt_skip_set.json FIRST.\n"
            "## Section 15r - Defense Surface (traverse/bypass these)\n"
            "_No guards found._\n"
            "## Section 15s - Full-Audit Results (what the audit already found)\n"
            "_No prior results._\n"
            "## TASK\nhunt\n"
        )
        # brain_prime present (callable), but no hacker-question signal.
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertEqual(r["verdict"], "fail-no-capability-adoption")
        self.assertEqual(r["missing_pillars"], ["capability-adoption"])

    def test_06_non_hunt_lane_skips(self):
        r = hbc.evaluate_brief("nothing", lane_type="filing")
        self.assertEqual(r["verdict"], "pass-not-hunt-lane")

    def test_07_valid_rebuttal_overrides(self):
        brief = "Lane H1: hunt\n<!-- pr9a-rebuttal: orchestrator preamble owns recall -->\n"
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertEqual(r["verdict"], "ok-rebuttal")
        self.assertEqual(r["rebuttal"], "orchestrator preamble owns recall")

    def test_08_oversized_and_empty_rebuttal_ignored(self):
        big = "x" * 250
        brief = f"Lane H1: hunt\n<!-- pr9a-rebuttal: {big} -->\n"
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertTrue(r["verdict"].startswith("fail-"))
        brief2 = "Lane H1: hunt\n<!-- pr9a-rebuttal:  -->\n"
        r2 = hbc.evaluate_brief(brief2, lane_type="hunt")
        self.assertTrue(r2["verdict"].startswith("fail-"))

    def test_09_missing_pillars_lists_all(self):
        r = hbc.evaluate_brief("hunt with nothing useful", lane_type="hunt")
        self.assertEqual(
            set(r["missing_pillars"]),
            {
                "mcp-first-block",
                "hunt-definition-skip-set",
                "capability-adoption",
                "defense-surface-section",
                "full-audit-results-section",
            },
        )
        # verdict reports first-in-priority (a).
        self.assertEqual(r["verdict"], "fail-no-mcp-first-block")

    def test_10_cli_json_smoke(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".md", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(COMPLETE_BRIEF)
            name = fh.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = hbc.main(
                    ["--prompt-file", name, "--lane-type", "hunt", "--json"]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["verdict"], "pass-complete")
            self.assertEqual(payload["schema"], hbc.SCHEMA)
        finally:
            os.unlink(name)

    def test_11_exit_codes(self):
        self.assertEqual(hbc._verdict_exit_code("pass-complete"), 0)
        self.assertEqual(hbc._verdict_exit_code("ok-rebuttal"), 0)
        self.assertEqual(hbc._verdict_exit_code("pass-not-hunt-lane"), 0)
        self.assertEqual(hbc._verdict_exit_code("fail-no-mcp-first-block"), 1)
        self.assertEqual(hbc._verdict_exit_code("fail-no-defense-surface-section"), 1)
        self.assertEqual(hbc._verdict_exit_code("fail-no-full-audit-results-section"), 1)
        self.assertEqual(hbc._verdict_exit_code("error"), 2)


    # ------------------------------------------------------------------
    # New pillar (d) + (e) cases
    # ------------------------------------------------------------------

    def _brief_without_15r_15s(self) -> str:
        """A brief that satisfies (a)+(b)+(c) but lacks 15r and 15s."""
        return (
            "## MCP-FIRST RECALL\n"
            "vault_resume_context vault_brain_prime_context vault_known_dead_ends\n"
            "A hunt is the FULL pipeline; consult hunt_skip_set.json FIRST.\n"
            "vault_per_function_hunter_brief hacker-questions\n"
        )

    def test_19_missing_defense_surface_section(self):
        brief = self._brief_without_15r_15s()
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertEqual(r["verdict"], "fail-no-defense-surface-section")
        self.assertIn("defense-surface-section", r["missing_pillars"])
        self.assertNotIn("mcp-first-block", r["missing_pillars"])
        self.assertNotIn("hunt-definition-skip-set", r["missing_pillars"])
        self.assertNotIn("capability-adoption", r["missing_pillars"])

    def test_20_missing_full_audit_results_section(self):
        # Has 15r but NOT 15s.
        brief = (
            self._brief_without_15r_15s()
            + "\n## Section 15r - Defense Surface (traverse/bypass these)\n"
            "No present guards extracted from in-scope source.\n"
        )
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertEqual(r["verdict"], "fail-no-full-audit-results-section")
        self.assertIn("full-audit-results-section", r["missing_pillars"])
        self.assertNotIn("defense-surface-section", r["missing_pillars"])

    def test_21_defense_surface_none_found_form_satisfies(self):
        # "(none found)" wording in combination with Section 15r header satisfies (d).
        brief = (
            self._brief_without_15r_15s()
            + "\n## Section 15r - Defense Surface (traverse/bypass these)\n"
            "_No present guards extracted from in-scope source._\n"
            "## Section 15s - Full-Audit Results (what the audit already found)\n"
            "_The pipeline already ran detectors._\n"
        )
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertNotIn("defense-surface-section", r["missing_pillars"])
        self.assertNotIn("full-audit-results-section", r["missing_pillars"])
        self.assertEqual(r["verdict"], "pass-complete")

    def test_22_defense_surface_pillar_independent(self):
        # Pillar (d) fires on its own when (a)+(b)+(c) are all present.
        brief = (
            "## MCP-FIRST RECALL\n"
            "vault_resume_context vault_brain_prime_context vault_known_dead_ends\n"
            "A hunt is the FULL pipeline; consult hunt_skip_set.json FIRST.\n"
            "vault_per_function_hunter_brief hacker-questions\n"
            "## Section 15s - Full-Audit Results (what the audit already found)\n"
            "_already found_\n"
        )
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertEqual(r["verdict"], "fail-no-defense-surface-section")
        self.assertEqual(r["missing_pillars"], ["defense-surface-section"])

    def test_23_full_audit_results_pillar_independent(self):
        # Pillar (e) fires on its own when (a)+(b)+(c)+(d) are all present.
        brief = (
            "## MCP-FIRST RECALL\n"
            "vault_resume_context vault_brain_prime_context vault_known_dead_ends\n"
            "A hunt is the FULL pipeline; consult hunt_skip_set.json FIRST.\n"
            "vault_per_function_hunter_brief hacker-questions\n"
            "## Section 15r - Defense Surface (traverse/bypass these)\n"
            "_No guards found._\n"
        )
        r = hbc.evaluate_brief(brief, lane_type="hunt")
        self.assertEqual(r["verdict"], "fail-no-full-audit-results-section")
        self.assertEqual(r["missing_pillars"], ["full-audit-results-section"])

    def test_24_filing_lane_unaffected_by_new_pillars(self):
        # A filing brief with no 15r/15s still passes as pass-not-hunt-lane.
        r = hbc.evaluate_brief("just file the thing", lane_type="filing")
        self.assertEqual(r["verdict"], "pass-not-hunt-lane")
        self.assertEqual(r["missing_pillars"], [])

    def test_25_all_five_missing_on_empty_brief(self):
        r = hbc.evaluate_brief("", lane_type="hunt")
        self.assertEqual(
            set(r["missing_pillars"]),
            {
                "mcp-first-block",
                "hunt-definition-skip-set",
                "capability-adoption",
                "defense-surface-section",
                "full-audit-results-section",
            },
        )

    def test_26_enriched_brief_with_15r_15s_passes(self):
        # Simulate what dispatch-agent-with-prebriefing.py renders: a full
        # enriched brief containing both section headers.
        enriched = COMPLETE_BRIEF  # already has 15r + 15s.
        r = hbc.evaluate_brief(enriched, lane_type="hunt")
        self.assertEqual(r["verdict"], "pass-complete")
        self.assertEqual(r["missing_pillars"], [])
        evidence_d = r["pillar_evidence"]["defense_surface"]
        evidence_e = r["pillar_evidence"]["full_audit_results"]
        self.assertTrue(evidence_d["ok"])
        self.assertTrue(evidence_e["ok"])
        self.assertTrue(len(evidence_d["hits"]) >= 1)
        self.assertTrue(len(evidence_e["hits"]) >= 1)


class DispatchWiringTests(unittest.TestCase):
    def setUp(self):
        # Always neutralize the spawn-worker dispatch guard so --dispatch can
        # reach the completeness gate in these tests.
        self._saved_env = {}
        for k in (
            prebriefing.SPAWN_WORKER_BYPASS_ENV_VAR,
            prebriefing.SPAWN_WORKER_BYPASS_REASON_ENV_VAR,
            prebriefing.HUNT_BRIEF_COMPLETENESS_WARN_ENV_VAR,
            prebriefing.HUNT_BRIEF_COMPLETENESS_DISABLE_ENV_VAR,
        ):
            self._saved_env[k] = os.environ.get(k)
        os.environ[prebriefing.SPAWN_WORKER_BYPASS_ENV_VAR] = "1"
        os.environ[prebriefing.SPAWN_WORKER_BYPASS_REASON_ENV_VAR] = "unit-test"
        os.environ.pop(
            prebriefing.HUNT_BRIEF_COMPLETENESS_WARN_ENV_VAR, None
        )
        os.environ.pop(
            prebriefing.HUNT_BRIEF_COMPLETENESS_DISABLE_ENV_VAR, None
        )

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_12_runner_non_hunt_lane(self):
        r = prebriefing.run_hunt_brief_completeness_check(
            "anything", lane_type="filing"
        )
        self.assertEqual(r["status"], "not-hunt-lane")
        self.assertEqual(r["verdict"], "pass-not-hunt-lane")

    def test_13_runner_disabled_env(self):
        os.environ[prebriefing.HUNT_BRIEF_COMPLETENESS_DISABLE_ENV_VAR] = "1"
        try:
            r = prebriefing.run_hunt_brief_completeness_check(
                "incomplete", lane_type="hunt"
            )
            self.assertEqual(r["status"], "disabled")
        finally:
            os.environ.pop(
                prebriefing.HUNT_BRIEF_COMPLETENESS_DISABLE_ENV_VAR, None
            )

    def test_14_runner_complete_brief(self):
        r = prebriefing.run_hunt_brief_completeness_check(
            COMPLETE_BRIEF, lane_type="hunt"
        )
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["verdict"], "pass-complete")

    def _run_main_dispatch(self, prompt: str, lane_type: str) -> int:
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = prebriefing.main(
                [
                    "--prompt",
                    prompt,
                    "--lane-type",
                    lane_type,
                    "--severity",
                    "HIGH",
                    "--no-infer",
                    "--dispatch",
                    "--claude-bin",
                    "/bin/echo",
                ]
            )
        return rc

    def test_15_dispatch_refuses_incomplete_hunt(self):
        rc = self._run_main_dispatch("Lane H1: hunt for bugs", "hunt")
        self.assertEqual(rc, prebriefing.EXIT_HUNT_BRIEF_COMPLETENESS_REFUSED)

    def test_16_dispatch_passes_complete_hunt(self):
        rc = self._run_main_dispatch(COMPLETE_BRIEF, "hunt")
        # /bin/echo returns rc=0; the gate did not block.
        self.assertEqual(rc, 0)

    def test_17_dispatch_warn_only_downgrades(self):
        os.environ[prebriefing.HUNT_BRIEF_COMPLETENESS_WARN_ENV_VAR] = "1"
        try:
            rc = self._run_main_dispatch("Lane H1: hunt for bugs", "hunt")
            # warn-only: incomplete brief still dispatches (echo rc=0).
            self.assertEqual(rc, 0)
        finally:
            os.environ.pop(
                prebriefing.HUNT_BRIEF_COMPLETENESS_WARN_ENV_VAR, None
            )

    def test_18_dispatch_non_hunt_lane_not_blocked(self):
        rc = self._run_main_dispatch("file the submission", "filing")
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
