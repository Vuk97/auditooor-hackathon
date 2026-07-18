"""Regression tests for tools/dispatch-template.py.

For each of the 5 dispatch templates this suite asserts:
  * a complete prompt passes (exit 0)
  * a prompt with one required field stripped fails (exit 1) AND the
    matching refusal_message is printed to stderr.

Bonus: a "before/after" scenario where a real-world sloppy prompt fails
the validator and a polished prompt passes — concrete evidence the
template adds value.

The tests load the validator module directly via importlib because the
script filename ``dispatch-template.py`` contains a hyphen.
"""
from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import re
import sys
import tempfile
import unittest
import contextlib
from typing import Dict, List


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE_DIR = REPO_ROOT / "reference" / "dispatch-templates"
VALIDATOR_PATH = REPO_ROOT / "tools" / "dispatch-template.py"


def _load_validator():
    spec = importlib.util.spec_from_file_location("dispatch_template", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load dispatch-template.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Complete-prompt fixtures (one per template). Each block intentionally
# satisfies every required_inputs detect_pattern.
# ---------------------------------------------------------------------------
COMPLETE_PROMPTS: Dict[str, str] = {
    "source-extract": """
workspace_path: ~/audits/polymarket
target_files:
  - external/polymarket-clob/contracts/Vault.sol:120-260
hypotheses:
  - "_sendL1Bridge reads total instead of total - hold"
prior_failed_attempts: none (first attempt)
expected_output_shape: |
  JSON-bullet candidate list per template; max 8 candidates.
""",
    "adversarial-kill": """
workspace_path: ~/audits/base-azul
candidate_list:
  - id: FN7-A — bridge drain via shared verifier reuse
oos_text: |
  O-1: shared-verifier reuse already disclosed
truncation_flag: complete
expected_output_shape: |
  Per-candidate JSON block with verdict + contradiction_citation.
""",
    "harness-plan": """
workspace_path: ~/audits/polymarket
target_symbol: Vault._sendL1Bridge
invariant_or_impact: "withdrawals can drain hold-reserved funds"
existing_fixtures: none
prior_failed_attempts: none
expected_output_shape: |
  One plan object — no code; decision_gate must be set.
""",
    "fixture-map": """
workspace_path: ~/audits/polymarket
invariant_or_pattern_slug: withdrawable-per-share-division-before-multiplication
candidate_source_paths:
  - external/polymarket-clob/contracts/Vault.sol:200-340
existing_fixture_inventory: none
expected_output_shape: |
  One fixture-map object per pattern with provenance and smoke_command.
""",
    "paste-ready-review": """
workspace_path: ~/audits/polymarket
draft_path: submissions/staging/W03.md
impact_mapping_or_contract: "selected_impact: withdrawals can drain hold-reserved funds; severity_implied: Medium"
proof_artifact: poc_execution/W03/execution_manifest.json
live_proof_manifest: submissions/packaged/W03/live-proof/manifest.json
oos_check_path: submissions/staging/W03/OOS_CHECK.md
poc_execution_manifest: poc_execution/W03/execution_manifest.json
expected_output_shape: |
  Review object per output_schema; SAFE_TO_SUBMIT only on full pass.
""",
}


def _strip_input(prompt: str, input_name: str) -> str:
    """Remove every line that starts with ``<input_name>:`` from the prompt."""
    pat = re.compile(rf"(?im)^\s*{re.escape(input_name)}\s*[:=].*$")
    out_lines: List[str] = []
    skip_block = False
    for line in prompt.splitlines():
        if skip_block:
            # continuation of a YAML-ish block (indented)
            if line.startswith((" ", "\t", "-", "  -")):
                continue
            skip_block = False
        if pat.match(line):
            # if value is on same line vs block — handle both
            skip_block = line.rstrip().endswith(":") or line.rstrip().endswith("|")
            continue
        out_lines.append(line)
    return "\n".join(out_lines)


class TemplateLoadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dt = _load_validator()

    def test_all_five_templates_present(self) -> None:
        names = self.dt.list_templates(TEMPLATE_DIR)
        self.assertEqual(
            set(names),
            {"source-extract", "adversarial-kill", "harness-plan", "fixture-map", "paste-ready-review"},
            f"unexpected template inventory: {names}",
        )

    def test_every_template_loads_with_required_inputs(self) -> None:
        for name in COMPLETE_PROMPTS:
            with self.subTest(template=name):
                tpl = self.dt.load_template(name, TEMPLATE_DIR)
                self.assertEqual(tpl["name"], name)
                self.assertGreaterEqual(len(tpl["required_inputs"]), 4)
                self.assertGreaterEqual(len(tpl["refusal_rules"]), 1)
                self.assertIn("output_schema", tpl)
                self.assertIn("example_invocation", tpl)

    def test_every_detect_pattern_compiles(self) -> None:
        for name in COMPLETE_PROMPTS:
            tpl = self.dt.load_template(name, TEMPLATE_DIR)
            for entry in tpl["required_inputs"]:
                with self.subTest(template=name, input=entry["name"]):
                    re.compile(entry["detect_pattern"])

    def test_examples_in_templates_validate(self) -> None:
        """The example_invocation block in each template should itself validate."""
        for name in COMPLETE_PROMPTS:
            tpl = self.dt.load_template(name, TEMPLATE_DIR)
            example = tpl.get("example_invocation", "")
            ok, missing = self.dt.validate_prompt(tpl, example)
            with self.subTest(template=name):
                self.assertTrue(
                    ok, f"example for '{name}' failed validation; missing={missing}"
                )


class CompletePromptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dt = _load_validator()

    def test_source_extract_complete_prompt_passes(self) -> None:
        self._assert_complete("source-extract")

    def test_adversarial_kill_complete_prompt_passes(self) -> None:
        self._assert_complete("adversarial-kill")

    def test_harness_plan_complete_prompt_passes(self) -> None:
        self._assert_complete("harness-plan")

    def test_fixture_map_complete_prompt_passes(self) -> None:
        self._assert_complete("fixture-map")

    def test_paste_ready_review_complete_prompt_passes(self) -> None:
        self._assert_complete("paste-ready-review")

    def _assert_complete(self, name: str) -> None:
        tpl = self.dt.load_template(name, TEMPLATE_DIR)
        ok, missing = self.dt.validate_prompt(tpl, COMPLETE_PROMPTS[name])
        self.assertTrue(ok, f"complete prompt for '{name}' failed; missing={missing}")
        self.assertEqual(missing, [])


class MissingInputTests(unittest.TestCase):
    """For each template, drop one required input and assert the matching
    refusal_message is reported."""

    def setUp(self) -> None:
        self.dt = _load_validator()

    def _assert_missing(self, template_name: str, input_to_strip: str) -> None:
        tpl = self.dt.load_template(template_name, TEMPLATE_DIR)
        prompt = _strip_input(COMPLETE_PROMPTS[template_name], input_to_strip)
        ok, missing = self.dt.validate_prompt(tpl, prompt)
        self.assertFalse(
            ok,
            f"expected refusal for '{template_name}' missing '{input_to_strip}'",
        )
        names = {m["input"] for m in missing}
        self.assertIn(input_to_strip, names, f"refusal did not flag '{input_to_strip}': got {names}")
        # And the refusal_message should actually be the template's declared one.
        expected_msg = next(
            e["refusal_message"] for e in tpl["required_inputs"] if e["name"] == input_to_strip
        )
        actual_msg = next(m["refusal_message"] for m in missing if m["input"] == input_to_strip)
        self.assertEqual(actual_msg, expected_msg)

    def test_source_extract_missing_target_files(self) -> None:
        self._assert_missing("source-extract", "target_files")

    def test_source_extract_missing_hypotheses(self) -> None:
        self._assert_missing("source-extract", "hypotheses")

    def test_adversarial_kill_missing_truncation_flag(self) -> None:
        self._assert_missing("adversarial-kill", "truncation_flag")

    def test_adversarial_kill_missing_candidate_list(self) -> None:
        self._assert_missing("adversarial-kill", "candidate_list")

    def test_harness_plan_missing_invariant(self) -> None:
        self._assert_missing("harness-plan", "invariant_or_impact")

    def test_harness_plan_missing_existing_fixtures(self) -> None:
        self._assert_missing("harness-plan", "existing_fixtures")

    def test_fixture_map_missing_candidate_source_paths(self) -> None:
        self._assert_missing("fixture-map", "candidate_source_paths")

    def test_fixture_map_missing_existing_fixture_inventory(self) -> None:
        self._assert_missing("fixture-map", "existing_fixture_inventory")

    def test_paste_ready_review_missing_live_proof_manifest(self) -> None:
        self._assert_missing("paste-ready-review", "live_proof_manifest")

    def test_paste_ready_review_missing_poc_execution_manifest(self) -> None:
        self._assert_missing("paste-ready-review", "poc_execution_manifest")


class CliExitCodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dt = _load_validator()

    def _run(self, argv: List[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            rc = self.dt.main(argv)
        return rc, out_buf.getvalue(), err_buf.getvalue()

    def test_complete_prompt_exits_zero(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(COMPLETE_PROMPTS["source-extract"])
            path = fh.name
        try:
            rc, out, err = self._run(["--template", "source-extract", "--validate", path])
            self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
            self.assertIn("OK", out)
        finally:
            os.unlink(path)

    def test_missing_input_exits_one(self) -> None:
        sloppy = _strip_input(COMPLETE_PROMPTS["source-extract"], "target_files")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(sloppy)
            path = fh.name
        try:
            rc, out, err = self._run(["--template", "source-extract", "--validate", path])
            self.assertEqual(rc, 1)
            self.assertIn("REFUSE", err)
            self.assertIn("target_files", err)
        finally:
            os.unlink(path)

    def test_missing_template_exits_two(self) -> None:
        rc, out, err = self._run(["--template", "does-not-exist", "--validate", str(VALIDATOR_PATH)])
        self.assertEqual(rc, 2)
        self.assertIn("not found", err)

    def test_no_args_exits_two(self) -> None:
        rc, out, err = self._run([])
        self.assertEqual(rc, 2)


class BeforeAfterDemoTests(unittest.TestCase):
    """Bonus: prove the template adds value by running a sloppy real-world
    prompt (the kind that produced the 96-question off-task tangent on
    2026-04-28) through the validator, then validating a polished version."""

    def setUp(self) -> None:
        self.dt = _load_validator()
        self.tpl = self.dt.load_template("source-extract", TEMPLATE_DIR)

    SLOPPY_PROMPT = (
        "Hey Kimi, take a look at the polymarket repo and see if you can "
        "find any interesting bugs in the fee module. Whatever you think "
        "looks risky. Thanks!\n"
    )

    POLISHED_PROMPT = """
workspace_path: ~/audits/polymarket
target_files:
  - external/polymarket-fees/contracts/NegRiskFeeModule.sol:1-260
hypotheses:
  - fee accrual underflow when paused
  - rounding direction lets users redeem more than deposited
prior_failed_attempts: |
  Kimi 2026-04-28 returned a 96-step deep-audit (off-task). Killed.
  Reason: prompt lacked target_files and hypotheses.
expected_output_shape: |
  JSON-bullet candidate list with source_files_and_lines, bug_shape,
  reachable_non_privileged_path, scope_risk, oos_risk; max 6 candidates;
  no severity prose.
"""

    def test_sloppy_prompt_is_refused(self) -> None:
        ok, missing = self.dt.validate_prompt(self.tpl, self.SLOPPY_PROMPT)
        self.assertFalse(ok)
        # All five inputs are missing in this sloppy prompt:
        names = {m["input"] for m in missing}
        for required in (
            "workspace_path",
            "target_files",
            "hypotheses",
            "prior_failed_attempts",
            "expected_output_shape",
        ):
            self.assertIn(required, names, f"sloppy prompt should also miss '{required}'")

    def test_polished_prompt_passes(self) -> None:
        ok, missing = self.dt.validate_prompt(self.tpl, self.POLISHED_PROMPT)
        self.assertTrue(
            ok,
            f"polished prompt unexpectedly failed: missing={missing}",
        )

    def test_demo_difference_is_not_zero(self) -> None:
        _, sloppy_missing = self.dt.validate_prompt(self.tpl, self.SLOPPY_PROMPT)
        _, polished_missing = self.dt.validate_prompt(self.tpl, self.POLISHED_PROMPT)
        self.assertGreater(len(sloppy_missing), 0)
        self.assertEqual(len(polished_missing), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
