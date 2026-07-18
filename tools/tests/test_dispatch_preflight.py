"""Regression tests for tools/dispatch-preflight.py.

PR #535 (Wave 8 §8). The preflight wrapper turns provider-dispatch
validation from "optional" into a hard gate for the 5 expensive task
types (source-extract / adversarial-kill / harness-plan / fixture-map /
paste-ready-review).

Test plan
---------

For every one of the 5 task types we assert:

* A valid prompt is dispatched to the (mocked) provider.
* A sloppy prompt is REFUSED, exits 1, and writes a REFUSED audit row.

In addition we exercise:

* ``BYPASS_DISPATCH_PREFLIGHT=1`` skips the validator but still audits
  with status BYPASSED, and dispatches.
* The audit JSONL round-trips: prompt-sha256 + provider_output_path +
  template_id + status are all present in the row we wrote.
* No real LLM is ever called — the underlying dispatcher is replaced
  with an echo-script via ``--mock-dispatcher`` so we never burn tokens.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import Dict, List, Optional, Tuple


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE_DIR = REPO_ROOT / "reference" / "dispatch-templates"
PACKET_DIR = REPO_ROOT / "reference" / "dispatch-packets"
PREFLIGHT_PATH = REPO_ROOT / "tools" / "dispatch-preflight.py"
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from lib.mcp_evidence_receipt import build_receipt  # noqa: E402


def _load_preflight():
    """Load tools/dispatch-preflight.py as a module (filename has hyphen)."""
    spec = importlib.util.spec_from_file_location(
        "dispatch_preflight", PREFLIGHT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load dispatch-preflight.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Mock dispatcher: a tiny Python script that exits 0 and prints a marker.
# It also dumps its argv into a sidecar JSON we can read in tests so we
# verify the wrapper handed it the right flags.
# ---------------------------------------------------------------------------
_MOCK_DISPATCHER_SOURCE = textwrap.dedent(
    """
    #!/usr/bin/env python3
    import json, os, pathlib, sys
    argv_dump = pathlib.Path(os.environ.get("MOCK_DISPATCH_ARGV_FILE", "/tmp/mock_dispatch_argv.json"))
    payload = {"argv": sys.argv[1:]}
    argv_dump.parent.mkdir(parents=True, exist_ok=True)
    argv_dump.write_text(json.dumps(payload))
    print("MOCK-DISPATCH-OK")
    sys.exit(0)
    """
).lstrip()


# ---------------------------------------------------------------------------
# Complete prompts (one per template) that satisfy every required input.
# For preflight-only lanes, that includes a locked Impact Contract for the
# task types that must not run before scope/impact are anchored.
# ---------------------------------------------------------------------------
COMPLETE_PROMPTS: Dict[str, str] = {
    "source-extract": """
workspace_path: ~/audits/polymarket
memory_context: |
  context_pack_id: auditooor.vault_context_pack.v1:dispatch:test
  context_pack_hash: test
  source_refs:
    - obsidian-vault/NEXT_LOOP.md
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
memory_context: |
  context_pack_id: auditooor.vault_context_pack.v1:dispatch:test
  context_pack_hash: test
  source_refs:
    - obsidian-vault/NEXT_LOOP.md
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
memory_context: |
  context_pack_id: auditooor.vault_context_pack.v1:dispatch:test
  context_pack_hash: test
  source_refs:
    - obsidian-vault/NEXT_LOOP.md
target_symbol: Vault._sendL1Bridge
invariant_or_impact: "withdrawals can drain hold-reserved funds"
existing_fixtures: none
prior_failed_attempts: none
expected_output_shape: |
  One plan object — no code; decision_gate must be set.

## Impact Contract
- selected_impact: Direct theft from in-scope bridge contracts (>=10% of locked value)
- severity_tier: Critical
- listed_impact_proven: true
- evidence_class: funds_flow_poc
- proof_contract:
  - funds_flow_poc proving bridge loss end-to-end
- oos_traps:
  - privileged_key
  - invalid_tee_or_zk_proof
- stop_condition: Executed bridge-loss proof shows non-privileged loss against in-scope contracts.
- downgrade_clauses:
  - component-only proof is NOT_SUBMIT_READY
""",
    "fixture-map": """
workspace_path: ~/audits/polymarket
memory_context: |
  context_pack_id: auditooor.vault_context_pack.v1:dispatch:test
  context_pack_hash: test
  source_refs:
    - obsidian-vault/NEXT_LOOP.md
invariant_or_pattern_slug: withdrawable-per-share-division-before-multiplication
candidate_source_paths:
  - external/polymarket-clob/contracts/Vault.sol:200-340
existing_fixture_inventory: none
expected_output_shape: |
  One fixture-map object per pattern with provenance and smoke_command.

## Impact Contract
- selected_impact: Temporary freezing of user funds (recoverable within a finalization window)
- severity_tier: High
- listed_impact_proven: true
- evidence_class: executed_with_manifest
- proof_contract:
  - real_component_harness showing finalization-window freeze
- oos_traps:
  - admin_or_governance_action
- stop_condition: Executed replay shows an in-scope user cannot finalize until the finalization window closes.
- downgrade_clauses:
  - source-only hypothesis remains NOT_SUBMIT_READY
""",
    "paste-ready-review": """
workspace_path: ~/audits/polymarket
memory_context: |
  context_pack_id: auditooor.vault_context_pack.v1:finalization:test
  context_pack_hash: test
  source_refs:
    - obsidian-vault/NEXT_LOOP.md
draft_path: submissions/staging/W03.md
impact_mapping_or_contract: "selected_impact: Engine API request validation bypass causing peer ban / fork follow-on; severity_tier: High; listed_impact_proven: true"
proof_artifact: poc_execution/W03/execution_manifest.json
live_proof_manifest: submissions/packaged/W03/live-proof/manifest.json
oos_check_path: submissions/staging/W03/OOS_CHECK.md
poc_execution_manifest: poc_execution/W03/execution_manifest.json
expected_output_shape: |
  Review object per output_schema; SAFE_TO_SUBMIT only on full pass.

## Impact Contract
- selected_impact: Engine API request validation bypass causing peer ban / fork follow-on
- severity_tier: High
- listed_impact_proven: true
- evidence_class: executed_with_manifest
- proof_contract:
  - poc_execution manifest proving the selected row
- oos_traps:
  - base_operated_infra
- stop_condition: Executed proof shows a non-operator peer can trigger the listed validation bypass and follow-on impact.
- downgrade_clauses:
  - missing execution manifest blocks paste-ready
""",
}

# A real-world sloppy prompt — the kind that triggered the 96-question
# Kimi off-task tangent on 2026-04-28. None of the required inputs are
# satisfied; preflight must refuse for every template.
SLOPPY_PROMPT = (
    "Hey Kimi, take a look at the polymarket repo and see if you can "
    "find any interesting bugs in the fee module. Whatever you think "
    "looks risky. Thanks!\n"
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------
class _PreflightTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.preflight = _load_preflight()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = pathlib.Path(self.tmp.name) / "ws"
        self.workspace.mkdir(parents=True)
        (self.workspace / "SEVERITY.md").write_text(
            textwrap.dedent(
                """
                # Synthetic Base Azul rubric

                ## Critical-tier listed impacts
                - Direct theft from in-scope bridge contracts (>=10% of locked value)
                - Total network shutdown of the canonical chain

                ## High-tier listed impacts
                - Engine API request validation bypass causing peer ban / fork follow-on
                - Temporary freezing of user funds (recoverable within a finalization window)

                ## Medium-tier listed impacts
                - Node resource consumption >=30%
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

        # Write the mock dispatcher.
        self.mock_dispatcher = pathlib.Path(self.tmp.name) / "mock_dispatcher.py"
        self.mock_dispatcher.write_text(_MOCK_DISPATCHER_SOURCE)
        self.mock_dispatcher.chmod(
            self.mock_dispatcher.stat().st_mode
            | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )

        # Tell the mock where to dump its argv (per-test isolation).
        self.argv_file = pathlib.Path(self.tmp.name) / "argv.json"
        os.environ["MOCK_DISPATCH_ARGV_FILE"] = str(self.argv_file)
        self.addCleanup(os.environ.pop, "MOCK_DISPATCH_ARGV_FILE", None)

        # Drop any leftover bypass env from prior tests.
        for var in (
            self.preflight.BYPASS_ENV_VAR,
            self.preflight.BYPASS_REASON_ENV_VAR,
            self.preflight.WORKSPACE_ENV_VAR,
        ):
            os.environ.pop(var, None)

    def _write_prompt(self, contents: str, suffix: str = ".md") -> pathlib.Path:
        path = pathlib.Path(self.tmp.name) / f"prompt{suffix}"
        path.write_text(contents)
        return path

    def _audit_path(self) -> pathlib.Path:
        return self.workspace / ".auditooor" / "dispatch_audit.jsonl"

    def _audit_rows(self) -> List[Dict]:
        path = self._audit_path()
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def _run(self, argv: List[str]) -> Tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            rc = self.preflight.main(argv)
        return rc, out_buf.getvalue(), err_buf.getvalue()

    def _base_argv(self, template: str, prompt_path: pathlib.Path) -> List[str]:
        return [
            "--template", template,
            "--prompt-file", str(prompt_path),
            "--workspace", str(self.workspace),
            "--mock-dispatcher", str(self.mock_dispatcher),
        ]


# ---------------------------------------------------------------------------
# Per-template smoke tests — valid prompt is dispatched (mocked).
# ---------------------------------------------------------------------------
class ValidPromptDispatchesTests(_PreflightTestBase):
    def _assert_valid_dispatches(self, template: str) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS[template])
        rc, out, err = self._run(self._base_argv(template, prompt))
        self.assertEqual(rc, 0, f"template={template} stderr={err!r}")

        rows = self._audit_rows()
        self.assertEqual(len(rows), 1, f"expected 1 audit row, got {rows}")
        row = rows[0]
        self.assertEqual(row["status"], "DISPATCHED")
        self.assertEqual(row["template_id"], template)
        self.assertEqual(row["dispatch_rc"], 0)
        self.assertIn("prompt_sha256", row)
        self.assertEqual(len(row["prompt_sha256"]), 64)
        self.assertIn("provider_output_path", row)

        # Verify the mock dispatcher actually got --task-type=<template>
        # and --prompt-file=<our prompt>.
        argv_payload = json.loads(self.argv_file.read_text())
        argv = argv_payload["argv"]
        self.assertIn("--task-type", argv)
        self.assertEqual(argv[argv.index("--task-type") + 1], template)
        self.assertIn("--prompt-file", argv)
        # Compare resolved paths so macOS /var -> /private/var symlink
        # does not produce false negatives.
        self.assertEqual(
            pathlib.Path(argv[argv.index("--prompt-file") + 1]).resolve(),
            prompt.resolve(),
        )

        # Provider output capture should contain the mock marker.
        out_path = pathlib.Path(row["provider_output_path"])
        self.assertTrue(out_path.is_file(), f"output not captured at {out_path}")
        self.assertIn("MOCK-DISPATCH-OK", out_path.read_text())

    def test_source_extract_valid_dispatches(self) -> None:
        self._assert_valid_dispatches("source-extract")

    def test_adversarial_kill_valid_dispatches(self) -> None:
        self._assert_valid_dispatches("adversarial-kill")

    def test_harness_plan_valid_dispatches(self) -> None:
        self._assert_valid_dispatches("harness-plan")

    def test_fixture_map_valid_dispatches(self) -> None:
        self._assert_valid_dispatches("fixture-map")

    def test_paste_ready_review_valid_dispatches(self) -> None:
        self._assert_valid_dispatches("paste-ready-review")

    def test_factory_liveness_extraction_uses_source_template_but_factory_task_type(self) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + [
            "--task-type", "factory-config-liveness-extraction",
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)

        row = self._audit_rows()[0]
        self.assertEqual(row["template_id"], "source-extract")
        self.assertEqual(row["task_type"], "factory-config-liveness-extraction")
        self.assertIn("factory-config-liveness-extraction", row["provider_output_path"])

        argv_payload = json.loads(self.argv_file.read_text())
        dispatcher_argv = argv_payload["argv"]
        self.assertEqual(
            dispatcher_argv[dispatcher_argv.index("--task-type") + 1],
            "factory-config-liveness-extraction",
        )

    def test_source_extraction_alias_uses_source_template_but_calibration_task_type(self) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + [
            "--task-type", "source-extraction",
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)

        row = self._audit_rows()[0]
        self.assertEqual(row["template_id"], "source-extract")
        self.assertEqual(row["task_type"], "source-extraction")
        self.assertIn("source-extraction", row["provider_output_path"])

        argv_payload = json.loads(self.argv_file.read_text())
        dispatcher_argv = argv_payload["argv"]
        self.assertEqual(
            dispatcher_argv[dispatcher_argv.index("--task-type") + 1],
            "source-extraction",
        )

    def test_factory_liveness_kill_uses_adversarial_template_but_factory_task_type(self) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS["adversarial-kill"])
        argv = self._base_argv("adversarial-kill", prompt) + [
            "--task-type", "factory-config-liveness-kill",
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)

        row = self._audit_rows()[0]
        self.assertEqual(row["template_id"], "adversarial-kill")
        self.assertEqual(row["task_type"], "factory-config-liveness-kill")
        self.assertIn("factory-config-liveness-kill", row["provider_output_path"])

        argv_payload = json.loads(self.argv_file.read_text())
        dispatcher_argv = argv_payload["argv"]
        self.assertEqual(
            dispatcher_argv[dispatcher_argv.index("--task-type") + 1],
            "factory-config-liveness-kill",
        )

    def test_factory_liveness_task_type_refuses_wrong_template(self) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("adversarial-kill", prompt) + [
            "--task-type", "factory-config-liveness-extraction",
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 2)
        self.assertIn("must use template 'source-extract'", err)

    def test_factory_liveness_example_packets_validate_in_dry_run(self) -> None:
        cases = (
            (
                "source-extract",
                "factory-config-liveness-extraction",
                "factory-config-liveness-extraction.example.md",
            ),
            (
                "adversarial-kill",
                "factory-config-liveness-kill",
                "factory-config-liveness-kill.example.md",
            ),
        )
        for template, task_type, filename in cases:
            with self.subTest(task_type=task_type):
                packet = PACKET_DIR / filename
                self.assertTrue(packet.is_file(), f"missing packet {packet}")
                argv = self._base_argv(template, packet) + [
                    "--task-type", task_type,
                    "--dry-run",
                ]
                rc, _out, err = self._run(argv)
                self.assertEqual(rc, 0, err)

        rows = self._audit_rows()
        self.assertEqual([row["status"] for row in rows], ["DRY_RUN", "DRY_RUN"])
        self.assertEqual(
            [row["task_type"] for row in rows],
            [
                "factory-config-liveness-extraction",
                "factory-config-liveness-kill",
            ],
        )


# ---------------------------------------------------------------------------
# Per-template refusal tests — sloppy prompt refused, audited, exits 1.
# ---------------------------------------------------------------------------
class SloppyPromptRefusedTests(_PreflightTestBase):
    def _assert_sloppy_refused(self, template: str) -> None:
        prompt = self._write_prompt(SLOPPY_PROMPT)
        rc, out, err = self._run(self._base_argv(template, prompt))
        self.assertEqual(rc, 1, f"template={template} expected refusal, got rc={rc}")
        self.assertIn("DISPATCH REFUSED", err)
        self.assertIn(template, err)

        rows = self._audit_rows()
        self.assertEqual(len(rows), 1, f"expected 1 REFUSED row, got {rows}")
        row = rows[0]
        self.assertEqual(row["status"], "REFUSED")
        self.assertEqual(row["template_id"], template)
        self.assertGreater(len(row["missing_inputs"]), 0)
        # We never invoke the dispatcher on refusal — argv-dump file
        # must not exist.
        self.assertFalse(
            self.argv_file.is_file(),
            "mock dispatcher was invoked on REFUSED path — should not happen",
        )

    def test_source_extract_sloppy_refused(self) -> None:
        self._assert_sloppy_refused("source-extract")

    def test_adversarial_kill_sloppy_refused(self) -> None:
        self._assert_sloppy_refused("adversarial-kill")

    def test_harness_plan_sloppy_refused(self) -> None:
        self._assert_sloppy_refused("harness-plan")

    def test_fixture_map_sloppy_refused(self) -> None:
        self._assert_sloppy_refused("fixture-map")

    def test_paste_ready_review_sloppy_refused(self) -> None:
        self._assert_sloppy_refused("paste-ready-review")


# ---------------------------------------------------------------------------
# Bypass behaviour tests
# ---------------------------------------------------------------------------
class BypassEnvVarTests(_PreflightTestBase):
    def test_bypass_dispatches_sloppy_prompt_with_audit(self) -> None:
        prompt = self._write_prompt(SLOPPY_PROMPT)
        os.environ[self.preflight.BYPASS_ENV_VAR] = "1"
        os.environ[self.preflight.BYPASS_REASON_ENV_VAR] = (
            "audit-tests: emergency dispatch — pager fire"
        )
        self.addCleanup(os.environ.pop, self.preflight.BYPASS_ENV_VAR, None)
        self.addCleanup(os.environ.pop, self.preflight.BYPASS_REASON_ENV_VAR, None)

        rc, out, err = self._run(self._base_argv("source-extract", prompt))
        self.assertEqual(rc, 0, f"bypass dispatch should succeed (mock); err={err!r}")
        self.assertIn("DISPATCH PREFLIGHT BYPASSED", err)

        rows = self._audit_rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["status"], "BYPASSED")
        self.assertEqual(
            row["bypass_reason"],
            "audit-tests: emergency dispatch — pager fire",
        )
        self.assertEqual(row["template_id"], "source-extract")
        self.assertEqual(row["dispatch_rc"], 0)
        self.assertIn("provider_output_path", row)

    def test_bypass_without_env_does_NOT_skip(self) -> None:
        # Sanity: same sloppy prompt without bypass env stays REFUSED.
        prompt = self._write_prompt(SLOPPY_PROMPT)
        rc, _out, err = self._run(self._base_argv("source-extract", prompt))
        self.assertEqual(rc, 1)
        self.assertIn("DISPATCH REFUSED", err)

    def test_bypass_requires_reason(self) -> None:
        prompt = self._write_prompt(SLOPPY_PROMPT)
        os.environ[self.preflight.BYPASS_ENV_VAR] = "1"
        self.addCleanup(os.environ.pop, self.preflight.BYPASS_ENV_VAR, None)

        rc, _out, err = self._run(self._base_argv("source-extract", prompt))
        self.assertEqual(rc, 1)
        self.assertIn("BYPASS_DISPATCH_PREFLIGHT_REASON", err)
        self.assertFalse(self.argv_file.is_file())
        rows = self._audit_rows()
        self.assertEqual(rows[0]["status"], "REFUSED")
        self.assertEqual(
            rows[0]["missing_inputs"],
            [self.preflight.BYPASS_REASON_ENV_VAR],
        )


class ImpactContractGateTests(_PreflightTestBase):
    def test_harness_plan_refuses_without_impact_contract_even_when_template_complete(self) -> None:
        prompt = self._write_prompt(
            """
workspace_path: ~/audits/polymarket
memory_context: |
  context_pack_id: auditooor.vault_context_pack.v1:dispatch:test
  context_pack_hash: test
  source_refs:
    - obsidian-vault/NEXT_LOOP.md
target_symbol: Vault._sendL1Bridge
invariant_or_impact: "Critical direct theft from bridge"
existing_fixtures: none
prior_failed_attempts: none
expected_output_shape: |
  One plan object.
"""
        )
        rc, _out, err = self._run(self._base_argv("harness-plan", prompt))
        self.assertEqual(rc, 1)
        self.assertIn("impact contract is not locked", err)
        self.assertIn("impact_contract_missing", err)

    def test_reportable_source_extract_refuses_without_contract(self) -> None:
        prompt = self._write_prompt(
            COMPLETE_PROMPTS["source-extract"]
            + "\nThis is a Critical direct-submit candidate.\n"
        )
        rc, _out, err = self._run(self._base_argv("source-extract", prompt))
        self.assertEqual(rc, 1)
        self.assertIn("impact contract is not locked", err)

    def test_source_extract_allows_severity_rubric_words_without_direct_submit(self) -> None:
        prompt = self._write_prompt(
            COMPLETE_PROMPTS["source-extract"]
            + "\n## Severity rubric\nCritical: direct theft.\nHigh: temporary freezing.\n"
        )
        argv = self._base_argv("source-extract", prompt) + ["--dry-run"]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)

    def test_scope_only_is_exempt_from_impact_contract(self) -> None:
        prompt = self._write_prompt(
            "workspace_path: ~/audits/base-azul\nFind the exact impact row to use.\n"
        )
        argv = self._base_argv("scope_only", prompt) + ["--dry-run"]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        rows = self._audit_rows()
        self.assertEqual(rows[0]["status"], "DRY_RUN")

    def test_impact_analysis_is_exempt_from_impact_contract(self) -> None:
        prompt = self._write_prompt(
            "workspace_path: ~/audits/base-azul\nAnalyze whether Snappy maps to any impact.\n"
        )
        argv = self._base_argv("impact_analysis", prompt) + ["--dry-run"]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)

    def test_snappy_mempool_contract_is_refused(self) -> None:
        prompt = self._write_prompt(
            COMPLETE_PROMPTS["harness-plan"].replace(
                "Direct theft from in-scope bridge contracts (>=10% of locked value)",
                "Mempool transaction propagation delay",
            )
            + "\nSnappy gossip decode candidate.\n"
        )
        rc, _out, err = self._run(self._base_argv("harness-plan", prompt))
        self.assertEqual(rc, 1)
        self.assertIn("snappy_gossip_decode_cannot_select_mempool_impact", err)


# ---------------------------------------------------------------------------
# Audit log persistence + round-trip tests
# ---------------------------------------------------------------------------
class AuditLogShapeTests(_PreflightTestBase):
    def test_audit_row_round_trip(self) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(self._base_argv("source-extract", prompt))
        self.assertEqual(rc, 0, err)

        path = self._audit_path()
        self.assertTrue(path.is_file(), f"audit log not written at {path}")
        rows = self._audit_rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]

        # Required keys for the round trip.
        for key in (
            "ts",
            "tool",
            "template_id",
            "prompt_path",
            "prompt_sha256",
            "status",
            "provider_output_path",
            "dispatch_rc",
            "dispatcher",
            "argv",
            "workspace",
            "workspace_source",
        ):
            self.assertIn(key, row, f"audit row missing required key '{key}'")

        # Sanity: the recorded sha256 matches a freshly-computed hash.
        import hashlib
        h = hashlib.sha256(prompt.read_bytes()).hexdigest()
        self.assertEqual(row["prompt_sha256"], h)

        # Sanity: timestamp parses as ISO-8601 UTC.
        self.assertRegex(row["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_audit_log_appends_across_calls(self) -> None:
        # Two attempts — one valid, one refused — should produce two rows.
        valid_prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        sloppy_prompt = pathlib.Path(self.tmp.name) / "sloppy.md"
        sloppy_prompt.write_text(SLOPPY_PROMPT)

        rc1, _o1, _e1 = self._run(self._base_argv("source-extract", valid_prompt))
        self.assertEqual(rc1, 0)

        rc2, _o2, _e2 = self._run(self._base_argv("source-extract", sloppy_prompt))
        self.assertEqual(rc2, 1)

        rows = self._audit_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["status"], "DISPATCHED")
        self.assertEqual(rows[1]["status"], "REFUSED")
        self.assertNotEqual(rows[0]["prompt_sha256"], rows[1]["prompt_sha256"])


# ---------------------------------------------------------------------------
# Misc: dry-run, missing prompt, refusal exit code
# ---------------------------------------------------------------------------
class MiscTests(_PreflightTestBase):
    def test_dry_run_does_not_invoke_dispatcher(self) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + ["--dry-run"]
        rc, _out, _err = self._run(argv)
        self.assertEqual(rc, 0)
        self.assertFalse(
            self.argv_file.is_file(),
            "dispatcher was called on --dry-run path",
        )
        rows = self._audit_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "DRY_RUN")

    def test_missing_prompt_file_exits_two(self) -> None:
        argv = [
            "--template", "source-extract",
            "--prompt-file", str(pathlib.Path(self.tmp.name) / "nope.md"),
            "--workspace", str(self.workspace),
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 2)
        self.assertIn("prompt file not found", err)

    def test_unknown_template_rejected_by_argparse(self) -> None:
        prompt = self._write_prompt("noop")
        argv = [
            "--template", "totally-fake-template",
            "--prompt-file", str(prompt),
            "--workspace", str(self.workspace),
        ]
        with self.assertRaises(SystemExit):
            self._run(argv)


class ModelFieldInAuditRowTests(_PreflightTestBase):
    """Lane-7 GAP-2: dispatch_audit.jsonl rows must carry a non-empty model field."""

    def test_dispatched_row_carries_model_field(self) -> None:
        """A DISPATCHED audit row must have a non-empty 'model' key."""
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(self._base_argv("source-extract", prompt))
        self.assertEqual(rc, 0, err)
        rows = self._audit_rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("model", rows[0], "audit row missing 'model' field")
        self.assertNotEqual(rows[0]["model"], "", "'model' field must not be empty")

    def test_refused_row_carries_model_field(self) -> None:
        """A REFUSED audit row must also carry a non-empty 'model' key."""
        prompt = self._write_prompt(SLOPPY_PROMPT)
        rc, _out, err = self._run(self._base_argv("source-extract", prompt))
        self.assertEqual(rc, 1)
        rows = self._audit_rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("model", rows[0], "REFUSED audit row missing 'model' field")
        self.assertNotEqual(rows[0]["model"], "")

    def test_model_resolves_from_provider_flag_kimi(self) -> None:
        """When --provider kimi is given, model should resolve to the kimi default."""
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + ["--provider", "kimi"]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = self._audit_rows()[0]
        # Env KIMI_MODEL may override; if not set, default is "kimi-for-coding".
        expected_model = os.environ.get("KIMI_MODEL", "kimi-for-coding")
        self.assertEqual(row["model"], expected_model)

    def test_model_is_unknown_when_provider_is_auto(self) -> None:
        """When provider is not specified (defaults to auto), model must be 'unknown'."""
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        # _base_argv does not pass --provider, so args.provider is None -> "auto" logic.
        argv = self._base_argv("source-extract", prompt)
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = self._audit_rows()[0]
        self.assertIn("model", row)
        # provider=None resolves to "unknown"
        self.assertEqual(row["model"], "unknown")

    def test_model_resolves_from_env_var(self) -> None:
        """When KIMI_MODEL env var is set, the audit row reflects it."""
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + ["--provider", "kimi"]
        os.environ["KIMI_MODEL"] = "kimi-custom-model-test"
        self.addCleanup(os.environ.pop, "KIMI_MODEL", None)
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = self._audit_rows()[0]
        self.assertEqual(row["model"], "kimi-custom-model-test")
        del os.environ["KIMI_MODEL"]  # restore eagerly too


# ---------------------------------------------------------------------------
# Lane 12 (Wave-6, 2026-05-19) — fail-closed MCP context prerequisites gate
# ---------------------------------------------------------------------------
import datetime
import time


class McpContextGateTests(_PreflightTestBase):
    """Tests for --require-mcp-context fail-closed dispatch gate (Lane 12)."""

    def _mcp_receipt_dir(self) -> pathlib.Path:
        d = self.workspace / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _write_fresh_receipt(self) -> pathlib.Path:
        """Write a fresh last_mcp_recall.json (recall_ts = now)."""
        d = self._mcp_receipt_dir()
        receipt_path = d / "last_mcp_recall.json"
        receipt_path.write_text(
            json.dumps({
                "context_pack_id": "auditooor.vault_context_pack.v1:resume:test",
                "context_pack_hash": "testhash",
                "workspace_path": str(self.workspace),
                "recall_ts": time.time(),
                "recall_iso": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "owner_tool": "TEST",
            }),
            encoding="utf-8",
        )
        return receipt_path

    def _write_stale_receipt(self, age_seconds: int = 7200) -> pathlib.Path:
        """Write a stale last_mcp_recall.json (recall_ts = now - age_seconds)."""
        d = self._mcp_receipt_dir()
        receipt_path = d / "last_mcp_recall.json"
        receipt_path.write_text(
            json.dumps({
                "context_pack_id": "auditooor.vault_context_pack.v1:resume:stale",
                "context_pack_hash": "stalehash",
                "workspace_path": str(self.workspace),
                "recall_ts": time.time() - age_seconds,
                "recall_iso": "2026-01-01T00:00:00Z",
                "owner_tool": "TEST",
            }),
            encoding="utf-8",
        )
        return receipt_path

    def _base_argv_mcp(self, template: str, prompt_path: pathlib.Path) -> List[str]:
        return self._base_argv(template, prompt_path) + ["--require-mcp-context"]

    def test_dispatch_passes_with_fresh_mcp_receipt(self) -> None:
        """When --require-mcp-context is set and a fresh receipt exists, dispatch succeeds."""
        self._write_fresh_receipt()
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(self._base_argv_mcp("source-extract", prompt))
        self.assertEqual(rc, 0, f"Expected dispatch to succeed with fresh receipt; err: {err}")
        rows = self._audit_rows()
        dispatched = [r for r in rows if r.get("status") == "DISPATCHED"]
        self.assertEqual(len(dispatched), 1, "Expected exactly one DISPATCHED row")

    def test_dispatch_refused_without_mcp_receipt(self) -> None:
        """When --require-mcp-context is set and no receipt exists, dispatch is REFUSED."""
        # No receipt written - ensure it doesn't exist
        receipt = self.workspace / ".auditooor" / "last_mcp_recall.json"
        receipt.unlink(missing_ok=True)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(self._base_argv_mcp("source-extract", prompt))
        self.assertEqual(rc, 1, f"Expected REFUSED (rc=1) without MCP receipt; got rc={rc}")
        self.assertIn("MCP context", err, f"Expected MCP context error in stderr; got: {err}")
        rows = self._audit_rows()
        refused = [r for r in rows if r.get("status") == "REFUSED"]
        self.assertEqual(len(refused), 1, "Expected one REFUSED audit row")
        self.assertEqual(refused[0].get("gate"), "mcp_context_prerequisites")

    def test_dispatch_refused_with_stale_mcp_receipt(self) -> None:
        """When --require-mcp-context is set and the receipt is >1h old, dispatch is REFUSED."""
        self._write_stale_receipt(age_seconds=7200)  # 2 hours old
        receipt = self.workspace / ".auditooor" / "last_mcp_recall.json"
        self.assertTrue(receipt.is_file(), "stale receipt should exist")
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(self._base_argv_mcp("source-extract", prompt))
        self.assertEqual(rc, 1, f"Expected REFUSED (rc=1) with stale receipt; got rc={rc}")
        self.assertIn("stale", err, f"Expected 'stale' in stderr; got: {err}")
        rows = self._audit_rows()
        refused = [r for r in rows if r.get("status") == "REFUSED"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0].get("gate"), "mcp_context_prerequisites")

    def test_dispatch_passes_without_flag(self) -> None:
        """When --require-mcp-context is NOT set, missing receipt does not block dispatch."""
        # No receipt at all - but no --require-mcp-context flag either
        receipt = self.workspace / ".auditooor" / "last_mcp_recall.json"
        receipt.unlink(missing_ok=True)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt)  # no --require-mcp-context
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, f"Expected dispatch without flag to succeed; err: {err}")

    def test_mcp_context_bypass_with_reason_passes(self) -> None:
        """MCP_CONTEXT_BYPASS=1 with a reason allows dispatch even without a fresh receipt."""
        receipt = self.workspace / ".auditooor" / "last_mcp_recall.json"
        receipt.unlink(missing_ok=True)
        os.environ[self.preflight.MCP_CONTEXT_BYPASS_ENV_VAR] = "1"
        os.environ[self.preflight.MCP_CONTEXT_BYPASS_REASON_ENV_VAR] = "emergency test bypass"
        self.addCleanup(os.environ.pop, self.preflight.MCP_CONTEXT_BYPASS_ENV_VAR, None)
        self.addCleanup(os.environ.pop, self.preflight.MCP_CONTEXT_BYPASS_REASON_ENV_VAR, None)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(self._base_argv_mcp("source-extract", prompt))
        self.assertEqual(rc, 0, f"Expected bypass to allow dispatch; err: {err}")
        rows = self._audit_rows()
        bypassed = [r for r in rows if r.get("status") == "MCP_CONTEXT_BYPASSED"]
        self.assertEqual(len(bypassed), 1, "Expected MCP_CONTEXT_BYPASSED audit row")
        self.assertEqual(bypassed[0]["bypass_reason"], "emergency test bypass")
        self.assertEqual(bypassed[0]["gate"], "mcp_context_prerequisites")

    def test_mcp_context_bypass_without_reason_refused(self) -> None:
        """MCP_CONTEXT_BYPASS=1 WITHOUT a reason is REFUSED (audited bypass requires reason)."""
        receipt = self.workspace / ".auditooor" / "last_mcp_recall.json"
        receipt.unlink(missing_ok=True)
        os.environ[self.preflight.MCP_CONTEXT_BYPASS_ENV_VAR] = "1"
        # No reason set
        os.environ.pop(self.preflight.MCP_CONTEXT_BYPASS_REASON_ENV_VAR, None)
        self.addCleanup(os.environ.pop, self.preflight.MCP_CONTEXT_BYPASS_ENV_VAR, None)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(self._base_argv_mcp("source-extract", prompt))
        self.assertEqual(rc, 1, f"Expected REFUSED without reason; got rc={rc}")
        rows = self._audit_rows()
        refused = [r for r in rows if r.get("status") == "REFUSED"]
        self.assertEqual(len(refused), 1)


class McpEvidenceReceiptGateTests(_PreflightTestBase):
    """Tests for --require-mcp-evidence-receipt dispatch gate."""

    def _write_evidence_receipt(self) -> pathlib.Path:
        d = self.workspace / ".auditooor" / "worker_packets"
        d.mkdir(parents=True, exist_ok=True)
        receipt = build_receipt(
            callable_name="vault_hacker_brief_for_lane",
            workspace=self.workspace,
            context_pack_id="auditooor.vault_hacker_brief_for_lane.v1:test",
            context_pack_hash="a" * 64,
            consumer_packet_hash="b" * 64,
            output_artifact_hash="c" * 64,
            required_call_set=["vault_hacker_brief_for_lane"],
            repo_sha="d" * 40,
            corpus_index_hash="e" * 64,
            timestamp="2026-05-21T00:00:00+00:00",
        )
        path = d / "canonical.mcp_evidence_receipt.json"
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def _base_argv_evidence(self, template: str, prompt_path: pathlib.Path, receipt_path: str) -> List[str]:
        return self._base_argv(template, prompt_path) + [
            "--require-mcp-evidence-receipt",
            receipt_path,
        ]

    def test_dispatch_passes_with_valid_mcp_evidence_receipt(self) -> None:
        receipt = self._write_evidence_receipt()
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(
            self._base_argv_evidence(
                "source-extract",
                prompt,
                str(receipt.relative_to(self.workspace)),
            )
        )
        self.assertEqual(rc, 0, err)
        dispatched = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"]
        self.assertEqual(len(dispatched), 1)

    def test_dispatch_refused_when_mcp_evidence_receipt_missing(self) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(
            self._base_argv_evidence(
                "source-extract",
                prompt,
                ".auditooor/worker_packets/missing.mcp_evidence_receipt.json",
            )
        )
        self.assertEqual(rc, 1)
        self.assertIn("MCP evidence receipt", err)
        refused = [r for r in self._audit_rows() if r.get("status") == "REFUSED"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0].get("gate"), "mcp_evidence_receipt")

    def test_dispatch_refused_when_mcp_evidence_receipt_outside_workspace(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("{}")
            handle.flush()
            prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
            rc, _out, err = self._run(
                self._base_argv_evidence("source-extract", prompt, handle.name)
            )
        self.assertEqual(rc, 1)
        self.assertIn("outside workspace", err)
        refused = [r for r in self._audit_rows() if r.get("status") == "REFUSED"]
        self.assertEqual(refused[0].get("gate"), "mcp_evidence_receipt")


class LocalJudgmentBundleGateTests(_PreflightTestBase):
    """Tests for High/Critical local candidate judgment bundle gating."""

    def _write_judgment_bundle(
        self,
        *,
        strict_allowed: bool = True,
        packets_emitted: int = 1,
        strict_blockers: Optional[List[str]] = None,
    ) -> pathlib.Path:
        d = self.workspace / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        path = d / "prove_top_leads_candidate_judgment_packet.json"
        payload = {
            "schema": self.preflight.CANDIDATE_JUDGMENT_SCHEMA,
            "summary": {
                "packets_emitted": packets_emitted,
                "strict_poc_planning_allowed": strict_allowed,
            },
            "strict_blockers": [] if strict_blockers is None else strict_blockers,
            "packets": [],
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def _base_argv_judgment(
        self,
        template: str,
        prompt_path: pathlib.Path,
        *,
        severity: str = "High",
        bundle_path: Optional[str] = None,
    ) -> List[str]:
        argv = self._base_argv(template, prompt_path) + ["--severity", severity]
        if bundle_path is not None:
            argv += ["--require-local-judgment-bundle", bundle_path]
        return argv

    def test_high_dispatch_refused_without_local_judgment_bundle(self) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(
            self._base_argv_judgment("source-extract", prompt, severity="High")
        )
        self.assertEqual(rc, 1)
        self.assertIn("Local judgment bundle", err)
        refused = [r for r in self._audit_rows() if r.get("status") == "REFUSED"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0].get("gate"), "local_judgment_bundle")
        self.assertEqual(refused[0].get("missing_inputs"), ["local_judgment_bundle"])

    def test_high_dispatch_passes_with_ready_local_judgment_bundle(self) -> None:
        bundle = self._write_judgment_bundle()
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(
            self._base_argv_judgment(
                "source-extract",
                prompt,
                severity="Critical",
                bundle_path=str(bundle.relative_to(self.workspace)),
            )
        )
        self.assertEqual(rc, 0, err)
        dispatched = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"]
        self.assertEqual(len(dispatched), 1)

    def test_high_dispatch_refused_when_local_judgment_bundle_blocked(self) -> None:
        bundle = self._write_judgment_bundle(
            strict_allowed=False,
            strict_blockers=["oos_not_cleared"],
        )
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(
            self._base_argv_judgment(
                "source-extract",
                prompt,
                bundle_path=str(bundle.relative_to(self.workspace)),
            )
        )
        self.assertEqual(rc, 1)
        self.assertIn("Local judgment bundle", err)
        refused = [r for r in self._audit_rows() if r.get("status") == "REFUSED"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0].get("gate"), "local_judgment_bundle")

    def test_high_dispatch_refused_when_local_judgment_bundle_outside_workspace(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("{}")
            handle.flush()
            prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
            rc, _out, err = self._run(
                self._base_argv_judgment(
                    "source-extract",
                    prompt,
                    severity="High",
                    bundle_path=handle.name,
                )
            )
        self.assertEqual(rc, 1)
        self.assertIn("outside workspace", err)
        refused = [r for r in self._audit_rows() if r.get("status") == "REFUSED"]
        self.assertEqual(refused[0].get("gate"), "local_judgment_bundle")

    def test_medium_dispatch_does_not_require_local_judgment_bundle(self) -> None:
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        rc, _out, err = self._run(
            self._base_argv_judgment("source-extract", prompt, severity="Medium")
        )
        self.assertEqual(rc, 0, err)
        dispatched = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"]
        self.assertEqual(len(dispatched), 1)

    # ------------------------------------------------------------------
    # Env-var fallback tests (AUDITOOOR_DISPATCH_SEVERITY +
    # AUDITOOOR_LOCAL_JUDGMENT_BUNDLE).  These verify the gap-closure path
    # that lets v3-provider-fanout-runner.py gate High/Critical dispatch
    # without modifying _build_command() per-row CLI args.
    # ------------------------------------------------------------------

    def test_high_refused_via_env_severity_without_cli_flag(self) -> None:
        """AUDITOOOR_DISPATCH_SEVERITY=High triggers gate even with no --severity CLI flag."""
        os.environ[self.preflight.DISPATCH_SEVERITY_ENV_VAR] = "High"
        self.addCleanup(os.environ.pop, self.preflight.DISPATCH_SEVERITY_ENV_VAR, None)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        # No --severity CLI flag, no --require-local-judgment-bundle
        argv = self._base_argv("source-extract", prompt)
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 1, f"Expected REFUSED but got rc={rc}, err={err!r}")
        self.assertIn("Local judgment bundle", err)
        refused = [r for r in self._audit_rows() if r.get("status") == "REFUSED"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0].get("gate"), "local_judgment_bundle")
        self.assertEqual(refused[0].get("missing_inputs"), ["local_judgment_bundle"])

    def test_critical_refused_via_env_severity_without_cli_flag(self) -> None:
        """AUDITOOOR_DISPATCH_SEVERITY=Critical triggers gate even with no --severity CLI flag."""
        os.environ[self.preflight.DISPATCH_SEVERITY_ENV_VAR] = "Critical"
        self.addCleanup(os.environ.pop, self.preflight.DISPATCH_SEVERITY_ENV_VAR, None)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt)
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 1, f"Expected REFUSED but got rc={rc}, err={err!r}")
        refused = [r for r in self._audit_rows() if r.get("status") == "REFUSED"]
        self.assertEqual(refused[0].get("gate"), "local_judgment_bundle")

    def test_high_passes_via_env_severity_and_env_bundle(self) -> None:
        """AUDITOOOR_DISPATCH_SEVERITY=High + AUDITOOOR_LOCAL_JUDGMENT_BUNDLE=<path> allows dispatch."""
        bundle = self._write_judgment_bundle()
        os.environ[self.preflight.DISPATCH_SEVERITY_ENV_VAR] = "High"
        os.environ[self.preflight.LOCAL_JUDGMENT_BUNDLE_ENV_VAR] = str(bundle)
        self.addCleanup(os.environ.pop, self.preflight.DISPATCH_SEVERITY_ENV_VAR, None)
        self.addCleanup(os.environ.pop, self.preflight.LOCAL_JUDGMENT_BUNDLE_ENV_VAR, None)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        # No CLI flags for severity or bundle
        argv = self._base_argv("source-extract", prompt)
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, f"Expected dispatch but got rc={rc}, err={err!r}")
        dispatched = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"]
        self.assertEqual(len(dispatched), 1)

    def test_env_bundle_refused_when_blocked(self) -> None:
        """Bundle path from env is validated; blocked bundle refuses via env path too."""
        bundle = self._write_judgment_bundle(
            strict_allowed=False,
            strict_blockers=["evidence_gap"],
        )
        os.environ[self.preflight.DISPATCH_SEVERITY_ENV_VAR] = "High"
        os.environ[self.preflight.LOCAL_JUDGMENT_BUNDLE_ENV_VAR] = str(bundle)
        self.addCleanup(os.environ.pop, self.preflight.DISPATCH_SEVERITY_ENV_VAR, None)
        self.addCleanup(os.environ.pop, self.preflight.LOCAL_JUDGMENT_BUNDLE_ENV_VAR, None)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt)
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 1)
        self.assertIn("Local judgment bundle", err)
        refused = [r for r in self._audit_rows() if r.get("status") == "REFUSED"]
        self.assertEqual(refused[0].get("gate"), "local_judgment_bundle")

    def test_env_bundle_refused_when_outside_workspace(self) -> None:
        """Bundle path from env is still rejected when it points outside workspace."""
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
            handle.write("{}")
            handle.flush()
            os.environ[self.preflight.DISPATCH_SEVERITY_ENV_VAR] = "High"
            os.environ[self.preflight.LOCAL_JUDGMENT_BUNDLE_ENV_VAR] = handle.name
            self.addCleanup(os.environ.pop, self.preflight.DISPATCH_SEVERITY_ENV_VAR, None)
            self.addCleanup(os.environ.pop, self.preflight.LOCAL_JUDGMENT_BUNDLE_ENV_VAR, None)
            prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
            argv = self._base_argv("source-extract", prompt)
            rc, _out, err = self._run(argv)
        self.assertEqual(rc, 1)
        self.assertIn("outside workspace", err)
        refused = [r for r in self._audit_rows() if r.get("status") == "REFUSED"]
        self.assertEqual(refused[0].get("gate"), "local_judgment_bundle")

    def test_medium_env_severity_does_not_require_bundle(self) -> None:
        """AUDITOOOR_DISPATCH_SEVERITY=Medium must NOT trigger the judgment bundle gate."""
        os.environ[self.preflight.DISPATCH_SEVERITY_ENV_VAR] = "Medium"
        self.addCleanup(os.environ.pop, self.preflight.DISPATCH_SEVERITY_ENV_VAR, None)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt)
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, f"Expected dispatch but got rc={rc}, err={err!r}")
        dispatched = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"]
        self.assertEqual(len(dispatched), 1)

    def test_cli_severity_takes_precedence_over_env_severity(self) -> None:
        """--severity Medium CLI flag overrides AUDITOOOR_DISPATCH_SEVERITY=High env var."""
        os.environ[self.preflight.DISPATCH_SEVERITY_ENV_VAR] = "High"
        self.addCleanup(os.environ.pop, self.preflight.DISPATCH_SEVERITY_ENV_VAR, None)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        # CLI says Medium; env says High.  Medium wins -> no bundle required.
        argv = self._base_argv("source-extract", prompt) + ["--severity", "Medium"]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, f"Expected dispatch but got rc={rc}, err={err!r}")
        dispatched = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"]
        self.assertEqual(len(dispatched), 1)


class PrebriefingAutoInvokeTests(_PreflightTestBase):
    """Phase -1 B / WF-7 #1 (iter18, 2026-05-23).

    Verifies dispatch-preflight auto-invokes
    tools/dispatch-agent-with-prebriefing.py for High/Critical severity
    and for prompts that cite R28+ rules, with --no-prebriefing opt-out
    and graceful MCP-fallback behavior.

    The wrapper is exercised through the public ``build_enriched_prompt``
    entry point. We inject a stub MCP caller (via monkey-patch on the
    loaded prebriefing module) so no MCP server subprocess is spawned.
    """

    _SKELETON_PAYLOAD: Dict[str, object] = {
        "schema": "auditooor.vault_dispatch_brief_skeleton.v1",
        "kind": "dispatch_brief_skeleton",
        "context_pack_id": "fake:dispatch_brief:preflight_test",
        "context_pack_hash": "a" * 64,
        "lane_type": "filing",
        "severity": "HIGH",
        "lane_specific_rules": ["R28", "R29", "R43"],
        "skeleton_sections": {
            "R29": "Commitment & Protection Analysis:\n- commitment: <<...>>",
            "R43": "Load-Bearing Bytes Attribution:\n- artifact: <<...>>",
        },
        "rubric_excerpt": {"rows": [], "parsed": False},
        "originality_anchors": [],
        "routine_violation_warnings": [],
        "busywork_refusals": [],
        "pre_submit_preview": [],
        "recall_summary": "RESUME: preflight prebriefing auto-invoke test",
        "usage_note": "Test stub - not a real MCP response.",
    }

    @staticmethod
    def _ok_caller(**kwargs: object) -> Dict[str, object]:
        return dict(PrebriefingAutoInvokeTests._SKELETON_PAYLOAD)

    @staticmethod
    def _failing_caller(**kwargs: object) -> Optional[Dict[str, object]]:
        return None

    @staticmethod
    def _phase_a_caller(**kwargs: object) -> Dict[str, object]:
        return {
            "schema": "auditooor.dispatch_phase_a_pillar_context.v1",
            "p1": {
                "context_pack_id": "auditooor.vault_invariant_library.v1:p1preflight",
                "context_pack_hash": "1" * 64,
                "invariants": [
                    {
                        "invariant_id": "INV-PREFLIGHT-001",
                        "statement": "A dispatch worker must see the relevant invariant snippet.",
                    }
                ],
            },
            "p3": {},
            "p5": {},
            "live_target_staleness": {"status": "not_checked"},
        }

    def _stub_mcp(self, caller=None) -> None:
        """Patch the prebriefing module's MCP caller for the duration of one test.

        The preflight loads the wrapper dynamically; we mirror that load so
        we can attach the stub to the same module instance the preflight
        import resolves to.
        """
        caller = caller or self._ok_caller
        wrapper_module = self.preflight._load_prebriefing_module()
        self.assertIsNotNone(
            wrapper_module,
            "prebriefing wrapper must be importable for these tests",
        )

        original = wrapper_module.call_vault_dispatch_brief_skeleton
        original_phase_a = wrapper_module.build_phase_a_pillar_context
        wrapper_module.call_vault_dispatch_brief_skeleton = caller  # type: ignore[attr-defined]
        wrapper_module.build_phase_a_pillar_context = self._phase_a_caller  # type: ignore[attr-defined]

        def _restore() -> None:
            wrapper_module.call_vault_dispatch_brief_skeleton = original  # type: ignore[attr-defined]
            wrapper_module.build_phase_a_pillar_context = original_phase_a  # type: ignore[attr-defined]

        self.addCleanup(_restore)

    def _bundle_path(self) -> str:
        """Write a passing local judgment bundle so the High-severity
        path can clear the bundle gate and reach the prebriefing block."""
        d = self.workspace / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        path = d / "prove_top_leads_candidate_judgment_packet.json"
        payload = {
            "schema": self.preflight.CANDIDATE_JUDGMENT_SCHEMA,
            "summary": {
                "packets_emitted": 1,
                "strict_poc_planning_allowed": True,
            },
            "strict_blockers": [],
            "packets": [],
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return str(path.relative_to(self.workspace))

    # --------------------------------------------------------------
    # Defaults
    # --------------------------------------------------------------

    def test_high_severity_auto_invokes_prebriefing_by_default(self) -> None:
        """HIGH severity should trigger prebriefing without any opt-in."""
        self._stub_mcp()
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + [
            "--severity", "High",
            "--require-local-judgment-bundle", self._bundle_path(),
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        rows = self._audit_rows()
        dispatched = [r for r in rows if r.get("status") == "DISPATCHED"]
        self.assertEqual(len(dispatched), 1)
        row = dispatched[0]
        self.assertIn("prebriefing", row)
        meta = row["prebriefing"]
        self.assertTrue(meta.get("invoked"), f"meta={meta!r}")
        self.assertEqual(meta.get("trigger_reason"), "severity-high-or-critical")
        self.assertEqual(meta.get("status"), "invoked")
        self.assertEqual(meta.get("skeleton_pack_id"), "fake:dispatch_brief:preflight_test")
        self.assertEqual(
            meta.get("phase_a_context_pack_ids", {}).get("p1"),
            "auditooor.vault_invariant_library.v1:p1preflight",
        )
        self.assertEqual(
            meta.get("phase_a_context_pack_hashes", {}).get("p1"),
            "1" * 64,
        )
        self.assertIn("enriched_prompt_path", meta)
        # The enriched prompt file on disk must carry BEGIN/END markers
        # and the original prompt text.
        enriched_path = pathlib.Path(meta["enriched_prompt_path"])
        self.assertTrue(enriched_path.is_file())
        enriched_text = enriched_path.read_text(encoding="utf-8")
        self.assertIn(
            "BEGIN dispatch-agent-with-prebriefing META-1 block",
            enriched_text,
        )
        self.assertIn(
            "END dispatch-agent-with-prebriefing META-1 block",
            enriched_text,
        )
        # Section markers from the skeleton format must be present.
        self.assertIn("## Section 15a", enriched_text)
        self.assertIn("## Section 15b", enriched_text)
        self.assertIn("## Section 15e - Phase A P1 invariant context", enriched_text)
        self.assertIn("MCP recall receipt", enriched_text)
        self.assertIn("INV-PREFLIGHT-001", enriched_text)
        self.assertIn("relevant invariant snippet", enriched_text)
        # The downstream dispatcher must have received the enriched prompt
        # path, NOT the raw prompt path.
        argv_payload = json.loads(self.argv_file.read_text())
        dispatcher_argv = argv_payload["argv"]
        prompt_idx = dispatcher_argv.index("--prompt-file")
        delivered = pathlib.Path(dispatcher_argv[prompt_idx + 1]).resolve()
        self.assertEqual(delivered, enriched_path.resolve())
        self.assertNotEqual(delivered, prompt.resolve())

    def test_critical_severity_auto_invokes_prebriefing(self) -> None:
        """CRITICAL severity should also trigger prebriefing."""
        self._stub_mcp()
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + [
            "--severity", "Critical",
            "--require-local-judgment-bundle", self._bundle_path(),
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"][0]
        meta = row["prebriefing"]
        self.assertTrue(meta.get("invoked"))
        self.assertEqual(meta.get("trigger_reason"), "severity-high-or-critical")

    def test_medium_severity_does_not_auto_invoke(self) -> None:
        """MEDIUM (no R28+ citation in prompt) must NOT auto-invoke."""
        self._stub_mcp()
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + [
            "--severity", "Medium",
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"][0]
        meta = row["prebriefing"]
        self.assertFalse(meta.get("invoked"), f"meta={meta!r}")
        self.assertEqual(meta.get("trigger_reason"), "skip-not-triggered")
        # Original prompt must be what the dispatcher saw.
        argv_payload = json.loads(self.argv_file.read_text())
        dispatcher_argv = argv_payload["argv"]
        prompt_idx = dispatcher_argv.index("--prompt-file")
        delivered = pathlib.Path(dispatcher_argv[prompt_idx + 1]).resolve()
        self.assertEqual(delivered, prompt.resolve())

    def test_r28_rule_citation_in_prompt_triggers_prebriefing(self) -> None:
        """A prompt body that cites R28 should trigger prebriefing even at LOW."""
        self._stub_mcp()
        custom_prompt = (
            COMPLETE_PROMPTS["source-extract"]
            + "\nMust comply with R28 multi-path escalation merge.\n"
        )
        prompt = self._write_prompt(custom_prompt)
        argv = self._base_argv("source-extract", prompt) + [
            "--severity", "Low",
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"][0]
        meta = row["prebriefing"]
        self.assertTrue(meta.get("invoked"))
        self.assertEqual(meta.get("trigger_reason"), "rule-r28-plus-cited")

    def test_r45_rule_citation_in_prompt_triggers_prebriefing(self) -> None:
        """Any R-rule >= R28 should match; verify R45 specifically."""
        self._stub_mcp()
        custom_prompt = (
            COMPLETE_PROMPTS["source-extract"]
            + "\nFollow R45 designed-as-intended precheck before filing.\n"
        )
        prompt = self._write_prompt(custom_prompt)
        argv = self._base_argv("source-extract", prompt)
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"][0]
        meta = row["prebriefing"]
        self.assertTrue(meta.get("invoked"))
        self.assertEqual(meta.get("trigger_reason"), "rule-r28-plus-cited")

    def test_lower_rule_numbers_do_not_trigger_prebriefing(self) -> None:
        """R-rules below R28 (R1, R18, R27) must NOT trigger the gate."""
        self._stub_mcp()
        custom_prompt = (
            COMPLETE_PROMPTS["source-extract"]
            + "\nFollow R18 in-process-vs-node-level and R27 adjacent-finding.\n"
        )
        prompt = self._write_prompt(custom_prompt)
        argv = self._base_argv("source-extract", prompt)
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"][0]
        meta = row["prebriefing"]
        self.assertFalse(meta.get("invoked"), f"meta={meta!r}")
        self.assertEqual(meta.get("trigger_reason"), "skip-not-triggered")

    # --------------------------------------------------------------
    # Opt-out
    # --------------------------------------------------------------

    def test_no_prebriefing_cli_flag_opts_out_high_severity(self) -> None:
        """--no-prebriefing forces skip even at HIGH."""
        self._stub_mcp()
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + [
            "--severity", "High",
            "--require-local-judgment-bundle", self._bundle_path(),
            "--no-prebriefing",
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"][0]
        meta = row["prebriefing"]
        self.assertFalse(meta.get("invoked"), f"meta={meta!r}")
        self.assertEqual(meta.get("trigger_reason"), "skip-no-prebriefing-cli")
        # Original prompt path was sent to dispatcher.
        argv_payload = json.loads(self.argv_file.read_text())
        dispatcher_argv = argv_payload["argv"]
        prompt_idx = dispatcher_argv.index("--prompt-file")
        delivered = pathlib.Path(dispatcher_argv[prompt_idx + 1]).resolve()
        self.assertEqual(delivered, prompt.resolve())

    def test_env_opt_out_disables_prebriefing(self) -> None:
        """AUDITOOOR_DISPATCH_NO_PREBRIEFING=1 also disables auto-invoke."""
        self._stub_mcp()
        os.environ[self.preflight.PREBRIEFING_OPT_OUT_ENV_VAR] = "1"
        self.addCleanup(
            os.environ.pop, self.preflight.PREBRIEFING_OPT_OUT_ENV_VAR, None
        )
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + [
            "--severity", "High",
            "--require-local-judgment-bundle", self._bundle_path(),
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"][0]
        meta = row["prebriefing"]
        self.assertFalse(meta.get("invoked"))
        self.assertEqual(meta.get("trigger_reason"), "skip-env-opt-out")

    # --------------------------------------------------------------
    # Graceful fallback
    # --------------------------------------------------------------

    def test_mcp_failure_falls_back_to_warn_stub_still_invokes(self) -> None:
        """When the MCP skeleton call returns None, the wrapper still emits
        a warn-stub BEGIN/END block. The dispatch must succeed; the audit
        row must record skeleton_unavailable=True alongside invoked=True."""
        self._stub_mcp(caller=self._failing_caller)
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + [
            "--severity", "High",
            "--require-local-judgment-bundle", self._bundle_path(),
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = [r for r in self._audit_rows() if r.get("status") == "DISPATCHED"][0]
        meta = row["prebriefing"]
        self.assertTrue(meta.get("invoked"), f"meta={meta!r}")
        self.assertTrue(meta.get("skeleton_unavailable"))
        # Warn-stub block should still have BEGIN/END markers in the
        # enriched prompt file on disk.
        enriched_path = pathlib.Path(meta["enriched_prompt_path"])
        enriched_text = enriched_path.read_text(encoding="utf-8")
        self.assertIn(
            "BEGIN dispatch-agent-with-prebriefing META-1 block",
            enriched_text,
        )
        self.assertIn("vault_dispatch_brief_skeleton unavailable", enriched_text)

    def test_prebriefing_meta_present_in_dry_run_row(self) -> None:
        """DRY_RUN audit rows must also carry the prebriefing meta block."""
        self._stub_mcp()
        prompt = self._write_prompt(COMPLETE_PROMPTS["source-extract"])
        argv = self._base_argv("source-extract", prompt) + [
            "--severity", "High",
            "--require-local-judgment-bundle", self._bundle_path(),
            "--dry-run",
        ]
        rc, _out, err = self._run(argv)
        self.assertEqual(rc, 0, err)
        row = [r for r in self._audit_rows() if r.get("status") == "DRY_RUN"][0]
        self.assertIn("prebriefing", row)
        self.assertTrue(row["prebriefing"].get("invoked"))

    def test_helper_function_recognizes_r28_plus(self) -> None:
        """Direct unit-test on the helper function for edge cases."""
        # R28, R29, R30 -> True
        self.assertTrue(self.preflight._prompt_triggers_prebriefing_via_rules("see R28"))
        self.assertTrue(self.preflight._prompt_triggers_prebriefing_via_rules("R29 plus R43"))
        self.assertTrue(self.preflight._prompt_triggers_prebriefing_via_rules("apply R56"))
        # R27, R18, R1 -> False
        self.assertFalse(self.preflight._prompt_triggers_prebriefing_via_rules("R27 only"))
        self.assertFalse(self.preflight._prompt_triggers_prebriefing_via_rules("R18"))
        self.assertFalse(self.preflight._prompt_triggers_prebriefing_via_rules("R1 R2 R3"))
        # No R-rule at all -> False
        self.assertFalse(self.preflight._prompt_triggers_prebriefing_via_rules("nothing"))
        # Embedded inside a word (R280 actually IS valid >= R28 so True).
        self.assertTrue(self.preflight._prompt_triggers_prebriefing_via_rules("R280"))
        # Lowercase r28 not detected (rules are uppercase by convention).
        self.assertFalse(self.preflight._prompt_triggers_prebriefing_via_rules("r28"))

    def test_helper_function_severity_check(self) -> None:
        """Direct unit-test on the severity-trigger helper."""
        self.assertTrue(self.preflight._severity_triggers_prebriefing("High"))
        self.assertTrue(self.preflight._severity_triggers_prebriefing("high"))
        self.assertTrue(self.preflight._severity_triggers_prebriefing("CRITICAL"))
        self.assertTrue(self.preflight._severity_triggers_prebriefing("critical"))
        self.assertFalse(self.preflight._severity_triggers_prebriefing("Medium"))
        self.assertFalse(self.preflight._severity_triggers_prebriefing("Low"))
        self.assertFalse(self.preflight._severity_triggers_prebriefing(None))
        self.assertFalse(self.preflight._severity_triggers_prebriefing(""))


if __name__ == "__main__":
    unittest.main()
