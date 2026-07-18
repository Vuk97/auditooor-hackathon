# <!-- r36-rebuttal: lane-LIFT-23-BRIEF-CLI-VALIDATOR-WIRE registered via
# tools/agent-pathspec-register.py (file: tools/tests/test_dispatch_brief_cli_validation.py).
# LIFT-23 ships the preflight unit + CLI tests covering all six required scenarios. -->
"""test_dispatch_brief_cli_validation.py - LIFT-23 unit tests for the
brief-cli-validator preflight wired into dispatch-agent-with-prebriefing.py.

The preflight is the LIFT-20 audit recommendation (c) deployment. It runs
``tools/brief-cli-validator.py`` against the prompt body BEFORE the
skeleton block is fetched, so stale CLI references in lane briefs surface
to the operator instead of wasting agent cycles invoking flags that do
not exist on the target tool.

Covers (>=6 cases per LIFT-23 brief Step 5):

  1. Valid brief (no tool invocations) -> 0 findings -> dispatch proceeds.
  2. Brief citing a real tool with a valid flag -> 0 findings -> dispatch
     proceeds.
  3. Brief citing a real tool with a stale flag -> 1 finding -> warn-only
     default, dispatch proceeds with WARN emitted.
  4. Strict mode same brief as (3) -> dispatch refused (rc=3), error block
     emitted to stderr.
  5. Brief citing a non-existent tool path -> finding with verdict
     ``fail-tool-missing-or-help-broken``, severity ``high``.
  6. Brief with ``--flag=value`` form is treated equivalently to
     ``--flag value`` (no false-positive stale-flag finding).
  7. Brief that references a literal ``tools/X.py`` placeholder (the
     validator's own self-test pattern) is correctly flagged as
     missing-tool.
  8. ``AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE=1`` short-circuits the
     preflight even when --strict-cli-validation is set.
  9. Helper ``run_brief_cli_validator_on_text`` returns a stable
     ``binary-missing`` record when the validator path is overridden to
     a non-existent file (backward-compat for older trees).
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from io import StringIO

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "brief-cli-validator.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "dispatch_agent_with_prebriefing_lift23", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dispatch_agent_with_prebriefing_lift23"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


prebriefing = _load_module()


# ---------------------------------------------------------------------------
# Helper: run the CLI in a subprocess so we exercise the real entrypoint.
# We pin --no-infer + explicit lane-type/severity so we do not depend on
# the MCP server being live (the skeleton call falls back gracefully).
# ---------------------------------------------------------------------------


def _run_cli(
    prompt_text: str,
    *,
    extra_args: list = None,
    env_overrides: dict = None,
) -> subprocess.CompletedProcess:
    args = [
        sys.executable,
        str(TOOL_PATH),
        "--no-infer",
        "--lane-type",
        "filing",
        "--severity",
        "HIGH",
    ]
    if extra_args:
        args.extend(extra_args)
    env = os.environ.copy()
    # Make sure we are not inheriting a disable flag from the test runner.
    env.pop("AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE", None)
    env.pop("AUDITOOOR_BRIEF_CLI_VALIDATOR_STRICT", None)
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        args,
        input=prompt_text,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


# ---------------------------------------------------------------------------
# Helper-level tests (don't need the CLI)
# ---------------------------------------------------------------------------


class HelperUnitTests(unittest.TestCase):
    def test_case_9_binary_missing_returns_soft_pass(self) -> None:
        """When validator path is overridden to a non-existent location
        the helper returns status='binary-missing' with 0 findings so
        downstream callers do not break."""
        result = prebriefing.run_brief_cli_validator_on_text(
            "irrelevant prompt body",
            validator_path=pathlib.Path("/nonexistent/brief-cli-validator.py"),
        )
        self.assertEqual(result["status"], "binary-missing")
        self.assertEqual(result["findings_count"], 0)
        self.assertEqual(result["highest_severity"], "none")

    def test_case_8_disable_env_short_circuits(self) -> None:
        os.environ["AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE"] = "1"
        try:
            result = prebriefing.run_brief_cli_validator_on_text(
                "python3 tools/brief-cli-validator.py --no-such-flag",
            )
        finally:
            os.environ.pop(
                "AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE", None
            )
        self.assertEqual(result["status"], "disabled")
        self.assertEqual(result["findings_count"], 0)

    def test_summary_emitter_writes_one_line_when_no_findings(self) -> None:
        buf = StringIO()
        prebriefing.emit_brief_cli_validator_summary(
            {
                "status": "ok",
                "findings_count": 0,
                "highest_severity": "none",
                "findings": [],
            },
            stream=buf,
            strict=False,
        )
        body = buf.getvalue()
        self.assertEqual(body.count("\n"), 1)
        self.assertIn("findings=0", body)
        self.assertIn("status=ok", body)

    def test_summary_emitter_writes_strict_block(self) -> None:
        buf = StringIO()
        prebriefing.emit_brief_cli_validator_summary(
            {
                "status": "ok",
                "findings_count": 2,
                "highest_severity": "medium",
                "findings": [
                    {
                        "verdict": "fail-stale-flag",
                        "tool_path": "tools/foo.py",
                        "flag": "--bar",
                        "line": 42,
                    },
                    {
                        "verdict": "fail-stale-flag",
                        "tool_path": "tools/baz.py",
                        "flag": "--qux",
                        "line": 99,
                    },
                ],
            },
            stream=buf,
            strict=True,
        )
        body = buf.getvalue()
        self.assertIn("FAIL", body)
        self.assertIn("dispatch refused", body)
        self.assertIn("--bar", body)
        self.assertIn("--qux", body)


# ---------------------------------------------------------------------------
# CLI-level tests (exercise the real entrypoint via subprocess)
# ---------------------------------------------------------------------------


class CliPreflightTests(unittest.TestCase):
    def test_case_1_no_tool_invocations_passes(self) -> None:
        """Brief that has no python3 tools/ invocations at all yields
        zero findings."""
        prompt = "## TASK\nReview the docs and report back. No tooling."
        proc = _run_cli(prompt)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("[BRIEF-CLI-VALIDATOR] findings=0", proc.stderr)

    def test_case_2_real_tool_valid_flag(self) -> None:
        """Brief citing the validator with the real --json flag should
        produce zero findings."""
        prompt = (
            "## TASK\n"
            "Run:\n"
            "```\n"
            "python3 tools/brief-cli-validator.py /tmp/foo.md --json\n"
            "```\n"
        )
        proc = _run_cli(prompt)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("findings=0", proc.stderr)

    def test_case_3_stale_flag_warn_mode_dispatches(self) -> None:
        """Brief with a stale flag yields 1 finding in warn mode but
        dispatch still completes (rc=0)."""
        prompt = (
            "## TASK\n"
            "```\n"
            "python3 tools/brief-cli-validator.py "
            "/tmp/foo.md --prompt-file=foo.md\n"
            "```\n"
        )
        proc = _run_cli(prompt)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("findings=1", proc.stderr)
        self.assertIn("WARN", proc.stderr)
        self.assertIn("--prompt-file", proc.stderr)
        # Enriched body still emitted.
        self.assertIn("META-1 block", proc.stdout)

    def test_case_4_stale_flag_strict_mode_refuses(self) -> None:
        """Same brief as (3) under --strict-cli-validation yields rc=3
        and the FAIL block is emitted."""
        prompt = (
            "## TASK\n"
            "```\n"
            "python3 tools/brief-cli-validator.py "
            "/tmp/foo.md --prompt-file=foo.md\n"
            "```\n"
        )
        proc = _run_cli(prompt, extra_args=["--strict-cli-validation"])
        self.assertEqual(
            proc.returncode,
            prebriefing.EXIT_BRIEF_CLI_VALIDATOR_REFUSED,
            msg=proc.stderr,
        )
        self.assertIn("FAIL", proc.stderr)
        self.assertIn("dispatch refused", proc.stderr)
        # Enriched body should NOT have been emitted to stdout when the
        # preflight refused dispatch.
        self.assertNotIn("META-1 block", proc.stdout)

    def test_case_5_nonexistent_tool_path_flagged_high_severity(self) -> None:
        """Brief that names a tool path not present on disk surfaces a
        ``fail-tool-missing-or-help-broken`` finding with severity high."""
        prompt = (
            "## TASK\n"
            "```\n"
            "python3 tools/this-tool-does-not-exist.py --whatever\n"
            "```\n"
        )
        proc = _run_cli(prompt)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("findings=", proc.stderr)
        # The brief contains a missing tool reference; the high-severity
        # marker tells the operator a binary is missing on disk.
        self.assertIn("severity=high", proc.stderr)

    def test_case_6_equals_form_flag_parsed_correctly(self) -> None:
        """A flag written as --json=foo is treated the same as --json foo
        so the validator does not false-positive on equals form."""
        prompt = (
            "## TASK\n"
            "```\n"
            "python3 tools/brief-cli-validator.py /tmp/foo.md --json=true\n"
            "```\n"
        )
        proc = _run_cli(prompt)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        # --json is a real flag; the equals-suffix should still parse to
        # --json (bare name) and find it in --help.
        self.assertIn("findings=0", proc.stderr)

    def test_case_7_literal_placeholder_tool_path_flagged(self) -> None:
        """The validator's own self-test anchor: a literal placeholder
        like tools/X.py (X being uppercase) is not a real tool, so the
        preflight surfaces it as a missing-tool finding (the LIFT-20
        positive control)."""
        prompt = (
            "## TASK\n"
            "```\n"
            "python3 tools/X.py --something\n"
            "```\n"
        )
        proc = _run_cli(prompt)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("findings=", proc.stderr)
        self.assertNotIn("findings=0", proc.stderr)

    def test_case_8_cli_disable_env_short_circuits_even_with_strict(
        self,
    ) -> None:
        """If AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE=1 is set, even
        --strict-cli-validation does not produce a refusal: the preflight
        is short-circuited at the helper level."""
        prompt = (
            "## TASK\n"
            "```\n"
            "python3 tools/brief-cli-validator.py "
            "/tmp/foo.md --no-such-flag\n"
            "```\n"
        )
        proc = _run_cli(
            prompt,
            extra_args=["--strict-cli-validation"],
            env_overrides={"AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE": "1"},
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("status=disabled", proc.stderr)
        self.assertIn("META-1 block", proc.stdout)


if __name__ == "__main__":
    unittest.main()
