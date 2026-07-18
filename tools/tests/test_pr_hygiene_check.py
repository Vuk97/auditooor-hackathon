from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "pr-hygiene-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("pr_hygiene_check", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr_hygiene_check"] = module
    spec.loader.exec_module(module)
    return module


pr_hygiene = _load_module()


COMPLETE_BODY = """\
# Demo PR

## PR Hygiene
- Changed-file scope:
  - exact file list: `tools/pr-hygiene-check.py`, `tools/tests/test_pr_hygiene_check.py`
  - why these files belong in one slice: adds the PR hygiene checker and its focused tests
- Checks run:
  - exact commands: `python3 -m unittest tools.tests.test_pr_hygiene_check -v`; `python3 tools/pr-hygiene-check.py PR.md --strict`; `python3 tools/vault-mcp-server.py --self-test`
  - result: pass
- MCP context:
  - context_pack_id: auditooor.vault_context_pack.v1:resume:abc123
  - context_pack_hash: abc123def456
  - source_refs: `docs/PR_HYGIENE_MEMORY_GATE_2026-05-06.md`
  - receipt_proof: none
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/**`, `tools/calibration/*.jsonl`
  - confirmation: excluded; not staged for this PR
"""


RECEIPT_FALLBACK_BODY = """\
## PR Hygiene
- Changed-file scope:
  - exact file list: `tools/pr-hygiene-check.py`
  - why these files belong in one slice: adds one checker
- Checks run:
  - exact commands: `python3 tools/pr-hygiene-check.py PR.md --strict`; `python3 tools/memory-context-load.py --workspace /tmp/ws --check --strict --require-proof --json`
  - result: pass
- MCP context:
  - context_pack_id: none
  - context_pack_hash: none
  - source_refs: `docs/PR_HYGIENE_MEMORY_GATE_2026-05-06.md`
  - receipt_proof: no MCP resources were available; used `docs/PR_HYGIENE_MEMORY_GATE_2026-05-06.md`
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/**`
  - confirmation: excluded generated receipts from the PR
"""


MCP_CLAIM_WITHOUT_CONTEXT_PACK_BODY = """\
## PR Hygiene
- Changed-file scope:
  - exact file list: `docs/README_BOUNDARY_2026-05-05.md`
  - why these files belong in one slice: updates a readme boundary note only
- Checks run:
  - exact commands: `git diff --check -- docs/README_BOUNDARY_2026-05-05.md`
  - result: pass
- MCP context:
  - context_pack_id: none
  - context_pack_hash: none
  - source_refs: none
  - receipt_proof: vault_resume_context was consulted before this PR body was drafted
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/**`
  - confirmation: excluded generated receipts from the PR
"""


MCP_CLAIM_WITH_CONTEXT_PACK_BODY = """\
## PR Hygiene
- Changed-file scope:
  - exact file list: `docs/README_BOUNDARY_2026-05-05.md`
  - why these files belong in one slice: updates a readme boundary note only
- Checks run:
  - exact commands: `python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":8}'`; `git diff --check -- docs/README_BOUNDARY_2026-05-05.md`
  - result: pass
- MCP context:
  - context_pack_id: auditooor.vault_context_pack.v1:resume:abc123
  - context_pack_hash: abc123def456
  - source_refs: `obsidian-vault/NEXT_LOOP.md`
  - receipt_proof: none
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/**`
  - confirmation: excluded generated receipts from the PR
"""


INCOMPLETE_BODY = """\
## PR Hygiene
- Changed-file scope:
  - exact file list: tools/
  - why these files belong in one slice:
- Checks run:
  - exact commands: tests pass
  - result:
- MCP context:
  - context_pack_id: none
  - context_pack_hash: none
  - source_refs: none
  - receipt_proof:
- Generated-file exclusion:
  - excluded paths/patterns:
  - confirmation:
"""


WORKFLOW_BODY_MISSING_GATE_COMMANDS = """\
## PR Hygiene
- Changed-file scope:
  - exact file list: `docs/WORKFLOW_ENFORCEMENT_ALWAYS_ON.md`
  - why these files belong in one slice: clarifies always-on workflow handoff rules
- Checks run:
  - exact commands: `python3 -m unittest tools.tests.test_pr_hygiene_check -v`
  - result: pass
- MCP context:
  - context_pack_id: none
  - context_pack_hash: none
  - source_refs: none
  - receipt_proof: MCP unavailable; local workflow doc was edited from repo state
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/**`
  - confirmation: excluded generated receipts from the PR
"""


WORKFLOW_BODY_WITH_GATE_COMMANDS = """\
## PR Hygiene
- Changed-file scope:
  - exact file list: `docs/WORKFLOW_ENFORCEMENT_ALWAYS_ON.md`
  - why these files belong in one slice: clarifies always-on workflow handoff rules
- Checks run:
  - exact commands: `python3 -m unittest tools.tests.test_pr_hygiene_check -v`; `python3 tools/pr-hygiene-check.py PR.md --strict`; `python3 tools/memory-context-load.py --workspace /tmp/ws --check --strict --require-proof --json`
  - result: pass
- MCP context:
  - context_pack_id: none
  - context_pack_hash: none
  - source_refs: `docs/WORKFLOW_ENFORCEMENT_ALWAYS_ON.md`, `docs/PR_HYGIENE_MEMORY_GATE_2026-05-06.md`
  - receipt_proof: MCP unavailable; local workflow docs were used as bounded context
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/**`
  - confirmation: excluded generated receipts from the PR
"""


WORKPACK_WORKFLOW_BODY_WITHOUT_WORKPACK_GATE = """\
## PR Hygiene
- Changed-file scope:
  - exact file list: `tools/workpack-validator.py`
  - why these files belong in one slice: tightens workpack handoff validation only
- Checks run:
  - exact commands: `python3 tools/pr-hygiene-check.py PR.md --strict`; `python3 tools/vault-mcp-server.py --self-test`
  - result: pass
- MCP context:
  - context_pack_id: auditooor.vault_context_pack.v1:resume:abc123
  - context_pack_hash: abc123def456
  - source_refs: `tools/workpack-validator.py`
  - receipt_proof: none
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/**`
  - confirmation: excluded generated receipts from the PR
"""


NON_WORKFLOW_BODY_WITHOUT_GATE_COMMANDS = """\
## PR Hygiene
- Changed-file scope:
  - exact file list: `docs/README_BOUNDARY_2026-05-05.md`
  - why these files belong in one slice: updates a readme boundary note only
- Checks run:
  - exact commands: `git diff --check -- docs/README_BOUNDARY_2026-05-05.md`
  - result: pass
- MCP context:
  - context_pack_id: auditooor.vault_context_pack.v1:resume:abc123
  - context_pack_hash: abc123def456
  - source_refs: `docs/README_BOUNDARY_2026-05-05.md`
  - receipt_proof: none
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/**`
  - confirmation: excluded generated receipts from the PR
"""


# --- PR #651 L1..L4 canonical-shape regression fixtures (loop 5 lock-in) ---
#
# These fixtures encode the contract the PR #651 body must satisfy:
# the body MAY make MCP-backed workflow claims (e.g. cite
# `vault_resume_context`, `mcp-backed`, `vault-mcp context`), and when it
# does the `claim_evidence` rule landed in `bcd5289c8` (see
# `_has_context_pack_source_evidence` in `tools/pr-hygiene-check.py`)
# requires the `## PR Hygiene` block to carry a real
# `mcp_context.context_pack_id`, `mcp_context.context_pack_hash`, and
# `mcp_context.source_refs`. The two fixtures below lock both directions
# of that contract: the canonical-shape pass case and the pack-id-stripped
# fail case.

PR651_LOOP_CANONICAL_BODY = """\
# DLT Workflow Gaps — PR #651 loop body (regression fixture)

This fixture mirrors the L1..L4 canonical PR #651 body shape: it makes an
MCP-backed workflow claim (cites `vault_resume_context` and the
`vault-mcp context_pack` provenance) and supplies the matching context
pack id/hash/source_refs evidence + workflow gate commands.

## PR Hygiene
- Changed-file scope:
  - exact file list: `tools/pr-hygiene-check.py`, `tools/tests/test_pr_hygiene_check.py`, `tools/vault-mcp-server.py`, `tools/batch-boundary-preflight.py`, `tools/workpack-validator.py`, `docs/PR_HYGIENE_MEMORY_GATE_2026-05-06.md`, `docs/WORKFLOW_ENFORCEMENT_ALWAYS_ON.md`
  - why these files belong in one slice: every change here hardens the same MCP-backed PR hygiene workflow boundary; splitting would force reviewers to context-switch between gate and evidence verified against the same run
  - exact commands: `python3 tools/pr-hygiene-check.py PR.md --strict`; `python3 tools/vault-mcp-server.py --self-test`; `python3 tools/memory-context-load.py --workspace /tmp/ws --check --strict --require-proof --json`; `python3 tools/workpack-validator.py /tmp/wp.md`; `python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":4}'`
- Checks run:
  - exact commands: `python3 tools/pr-hygiene-check.py PR.md --strict`; `python3 tools/vault-mcp-server.py --self-test`; `python3 tools/memory-context-load.py --workspace /tmp/ws --check --strict --require-proof --json`; `python3 tools/workpack-validator.py /tmp/wp.md`; `python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":4}'`
  - result: pass; strict PR hygiene gate returned ok=true; vault-mcp self-test green; memory-context-load --check --strict --require-proof returned a valid receipt
- MCP context:
  - context_pack_id: auditooor.vault_context_pack.v1:resume:4bafcc62fa5b65b7
  - context_pack_hash: 4bafcc62fa5b65b72dc9d7319931b67031e615ccd4901169ed5612c64e0ab0e1
  - source_refs: `vault://INDEX_active.md`, `vault://NEXT_LOOP.md`, `tools/pr-hygiene-check.py`, `tools/vault-mcp-server.py`, `tools/batch-boundary-preflight.py`, `tools/workpack-validator.py`, `docs/PR_HYGIENE_MEMORY_GATE_2026-05-06.md`
  - receipt_proof: `python3 tools/vault-mcp-server.py --call vault_resume_context` returned the context_pack id/hash above with a fallback to the active shared vault
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/llm_dispatch_*.json`, `tools/calibration/llm_budget_log.jsonl`, `.auditooor/**`
  - confirmation: excluded from staged commits; calibration logs explicitly NOT staged
"""


PR651_LOOP_BODY_MISSING_PACK_ID = """\
# DLT Workflow Gaps — PR #651 loop body (regression fixture, pack id stripped)

Same MCP-backed claim shape as the canonical fixture, but the
`mcp_context.context_pack_id` field is empty so `claim_evidence` must
fail and the PR hygiene gate must reject the body under --strict.

## PR Hygiene
- Changed-file scope:
  - exact file list: `tools/pr-hygiene-check.py`, `tools/tests/test_pr_hygiene_check.py`, `tools/vault-mcp-server.py`, `tools/batch-boundary-preflight.py`, `tools/workpack-validator.py`, `docs/PR_HYGIENE_MEMORY_GATE_2026-05-06.md`
  - why these files belong in one slice: every change here hardens the same MCP-backed PR hygiene workflow boundary
- Checks run:
  - exact commands: `python3 tools/pr-hygiene-check.py PR.md --strict`; `python3 tools/vault-mcp-server.py --self-test`; `python3 tools/memory-context-load.py --workspace /tmp/ws --check --strict --require-proof --json`; `python3 tools/workpack-validator.py /tmp/wp.md`; `python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":4}'`
  - result: pass
- MCP context:
  - context_pack_id: none
  - context_pack_hash: 4bafcc62fa5b65b72dc9d7319931b67031e615ccd4901169ed5612c64e0ab0e1
  - source_refs: `vault://INDEX_active.md`, `tools/pr-hygiene-check.py`, `tools/vault-mcp-server.py`
  - receipt_proof: none
- Generated-file exclusion:
  - excluded paths/patterns: `agent_outputs/llm_dispatch_*.json`, `tools/calibration/llm_budget_log.jsonl`
  - confirmation: excluded from staged commits
"""


class PrHygieneCheckTests(unittest.TestCase):
    def test_complete_pr_hygiene_block_passes(self):
        report = pr_hygiene.validate_pr_body(COMPLETE_BODY, pr_body_path="PR.md")

        self.assertTrue(report["ok"])
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["advisory"]["strict_exit_code"], 0)

    def test_receipt_proof_fallback_satisfies_mcp_context(self):
        report = pr_hygiene.validate_pr_body(RECEIPT_FALLBACK_BODY, pr_body_path="PR.md")

        self.assertTrue(report["ok"])
        mcp = next(check for check in report["checks"] if check["id"] == "mcp_context.provenance")
        self.assertEqual(mcp["status"], "pass")
        self.assertIn("receipt_proof fallback", mcp["message"])
        claim = next(
            check for check in report["checks"] if check["id"] == "mcp_context.claim_evidence"
        )
        self.assertEqual(claim["status"], "pass")
        self.assertEqual(claim["evidence"]["claims"], [])

    def test_mcp_workflow_claim_requires_context_pack_source_evidence(self):
        report = pr_hygiene.validate_pr_body(
            MCP_CLAIM_WITHOUT_CONTEXT_PACK_BODY,
            pr_body_path="PR.md",
        )

        self.assertFalse(report["ok"])
        claim = next(
            check for check in report["checks"] if check["id"] == "mcp_context.claim_evidence"
        )
        self.assertEqual(claim["status"], "fail")
        self.assertIn("mcp_context.claim_evidence", report["missing"])
        self.assertEqual(claim["evidence"]["claims"], ["vault_resume_context"])

    def test_mcp_workflow_claim_passes_with_context_pack_source_evidence(self):
        report = pr_hygiene.validate_pr_body(
            MCP_CLAIM_WITH_CONTEXT_PACK_BODY,
            pr_body_path="PR.md",
        )

        self.assertTrue(report["ok"], report)
        claim = next(
            check for check in report["checks"] if check["id"] == "mcp_context.claim_evidence"
        )
        self.assertEqual(claim["status"], "pass")
        self.assertEqual(claim["evidence"]["claims"], ["--call vault_resume_context"])

    def test_workflow_affecting_pr_requires_context_evidence_and_gate_commands(self):
        report = pr_hygiene.validate_pr_body(
            WORKFLOW_BODY_MISSING_GATE_COMMANDS,
            pr_body_path="PR.md",
        )

        self.assertFalse(report["ok"])
        workflow = next(
            check for check in report["checks"] if check["id"] == "workflow_handoff.enforcement"
        )
        self.assertEqual(workflow["status"], "fail")
        self.assertIn("workflow_handoff.enforcement", report["missing"])
        self.assertEqual(
            workflow["evidence"]["workflow_affecting_paths"],
            ["docs/WORKFLOW_ENFORCEMENT_ALWAYS_ON.md"],
        )
        self.assertIn("strict PR hygiene gate", workflow["evidence"]["missing_gate_commands"])
        self.assertIn("MCP/context gate", workflow["evidence"]["missing_gate_commands"])
        self.assertIn("source_refs", workflow["evidence"]["missing_context_evidence"])

    def test_workflow_affecting_pr_passes_with_context_evidence_and_gate_commands(self):
        report = pr_hygiene.validate_pr_body(
            WORKFLOW_BODY_WITH_GATE_COMMANDS,
            pr_body_path="PR.md",
        )

        self.assertTrue(report["ok"], report)
        workflow = next(
            check for check in report["checks"] if check["id"] == "workflow_handoff.enforcement"
        )
        self.assertEqual(workflow["status"], "pass")
        self.assertEqual(workflow["evidence"]["missing_gate_commands"], [])
        self.assertEqual(workflow["evidence"]["missing_context_evidence"], [])

    def test_workpack_affecting_pr_requires_workpack_validation_gate(self):
        report = pr_hygiene.validate_pr_body(
            WORKPACK_WORKFLOW_BODY_WITHOUT_WORKPACK_GATE,
            pr_body_path="PR.md",
        )

        self.assertFalse(report["ok"])
        workflow = next(
            check for check in report["checks"] if check["id"] == "workflow_handoff.enforcement"
        )
        self.assertEqual(workflow["status"], "fail")
        self.assertIn("workpack validation gate", workflow["evidence"]["missing_gate_commands"])

    def test_non_workflow_pr_does_not_require_workflow_gate_commands(self):
        report = pr_hygiene.validate_pr_body(
            NON_WORKFLOW_BODY_WITHOUT_GATE_COMMANDS,
            pr_body_path="PR.md",
        )

        self.assertTrue(report["ok"], report)
        workflow = next(
            check for check in report["checks"] if check["id"] == "workflow_handoff.enforcement"
        )
        self.assertEqual(workflow["status"], "pass")
        self.assertEqual(workflow["evidence"]["workflow_affecting_paths"], [])

    def test_incomplete_pr_hygiene_block_is_advisory_unless_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            pr_body = Path(tmp) / "PR.md"
            pr_body.write_text(INCOMPLETE_BODY, encoding="utf-8")

            advisory_output = io.StringIO()
            with contextlib.redirect_stdout(advisory_output):
                advisory_code = pr_hygiene.main([str(pr_body)], stdout=advisory_output)
            advisory_report = json.loads(advisory_output.getvalue())

            strict_output = io.StringIO()
            with contextlib.redirect_stdout(strict_output):
                strict_code = pr_hygiene.main([str(pr_body), "--strict"], stdout=strict_output)
            strict_report = json.loads(strict_output.getvalue())

        self.assertEqual(advisory_code, 0)
        self.assertEqual(strict_code, 1)
        self.assertFalse(advisory_report["ok"])
        self.assertEqual(advisory_report["missing"], strict_report["missing"])
        self.assertIn("changed_file_scope.exact_file_list", advisory_report["missing"])
        self.assertIn("checks.exact_commands", advisory_report["missing"])
        self.assertIn("mcp_context.provenance", advisory_report["missing"])
        self.assertIn(
            "generated_file_exclusion.confirmation",
            advisory_report["missing"],
        )


class PrHygieneCheckPr651LoopShapeRegressionTests(unittest.TestCase):
    """Lock the L1..L4 PR #651 canonical body shape against pr-hygiene-check.

    Pairs a passing fixture (canonical shape) with a failing fixture
    (context_pack_id stripped) so the `mcp_context.claim_evidence` rule
    landed in `bcd5289c8` cannot silently regress on PR #651 body refreshes.
    """

    def test_pr651_canonical_loop_body_passes_strict_gate(self):
        report = pr_hygiene.validate_pr_body(
            PR651_LOOP_CANONICAL_BODY,
            pr_body_path="PR.md",
        )

        self.assertTrue(report["ok"], report)
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["advisory"]["strict_exit_code"], 0)
        claim = next(
            check for check in report["checks"] if check["id"] == "mcp_context.claim_evidence"
        )
        self.assertEqual(claim["status"], "pass")
        # The canonical body cites the MCP-backed workflow claim explicitly,
        # so claim detection must fire and be satisfied by the pack
        # id/hash/source_refs evidence.
        self.assertNotEqual(claim["evidence"]["claims"], [])
        workflow = next(
            check for check in report["checks"] if check["id"] == "workflow_handoff.enforcement"
        )
        self.assertEqual(workflow["status"], "pass")

    def test_pr651_loop_body_without_context_pack_id_fails_strict_gate(self):
        report = pr_hygiene.validate_pr_body(
            PR651_LOOP_BODY_MISSING_PACK_ID,
            pr_body_path="PR.md",
        )

        self.assertFalse(report["ok"])
        self.assertEqual(report["advisory"]["strict_exit_code"], 1)
        self.assertIn("mcp_context.claim_evidence", report["missing"])
        claim = next(
            check for check in report["checks"] if check["id"] == "mcp_context.claim_evidence"
        )
        self.assertEqual(claim["status"], "fail")
        self.assertNotEqual(claim["evidence"]["claims"], [])


class PrHygieneCheckPr651Loop6CloseoutSummaryShapeRegressionTests(unittest.TestCase):
    """Lock the loop-6 PR #651 body's NEW Closeout Summary section shape.

    This is a body-shape regression test (not a pr-hygiene-check rule test):
    it asserts the canonical closeout-summary block format that Worker CC
    introduced in loop 6 so that subsequent loop refreshes (L7+) cannot
    silently regress the format Worker CC, T, N, D and future workers rely
    on for fast PR-body health auditing.

    The shape contract:
      1. Body MUST contain a level-2 heading exactly ``## Closeout Summary``.
      2. The section MUST contain a markdown table with the canonical
         column headers ``Check``, ``Status``, and ``Notes`` (in that
         order).
      3. The table MUST have at least one data row (i.e. it must not be
         the empty header-only stub).

    These three guards together prevent the most likely regressions:
    deleting the heading, renaming columns, or pasting an empty table
    placeholder.
    """

    LOOP6_PR_BODY_PATH = Path("/private/tmp/pr651-body-refresh-loop6.md")

    CANONICAL_CLOSEOUT_SUMMARY_BODY = """\
# Demo PR

## Closeout Summary

Latest workspace closeout from `~/audits/spark/.audit_logs/audit_closeout_manifest.json`.

| Check | Status | Notes |
|---|---|---|
| canonical-audit | PASS | 3/6 primary artifacts present |
| mcp-context | FAIL | memory context receipt incomplete; required=6 loaded=6 missing=0 stale=2 |
| pre-submit | FAIL | 1 High/Critical draft NOT_SUBMIT_READY |

## PR Hygiene
- placeholder
"""

    HEADING_MISSING_BODY = """\
# Demo PR

## Closeout Manifest

| Check | Status | Notes |
|---|---|---|
| canonical-audit | PASS | 3/6 primary artifacts present |

## PR Hygiene
- placeholder
"""

    COLUMNS_RENAMED_BODY = """\
# Demo PR

## Closeout Summary

| Name | Result | Detail |
|---|---|---|
| canonical-audit | PASS | 3/6 primary artifacts present |

## PR Hygiene
- placeholder
"""

    EMPTY_TABLE_BODY = """\
# Demo PR

## Closeout Summary

| Check | Status | Notes |
|---|---|---|

## PR Hygiene
- placeholder
"""

    @staticmethod
    def _extract_closeout_summary_table_rows(body: str) -> list[list[str]]:
        """Return the data rows under the canonical ``## Closeout Summary`` table.

        Returns an empty list when the heading or table is missing. The
        first two ``|...|`` lines (header + separator) are dropped; data
        rows are split on ``|`` with leading/trailing whitespace stripped.
        """

        lines = body.splitlines()
        try:
            heading_idx = next(
                idx for idx, line in enumerate(lines) if line.strip() == "## Closeout Summary"
            )
        except StopIteration:
            return []

        # Find the first non-blank, non-prose | ... | line under the heading.
        table_start = None
        for idx in range(heading_idx + 1, len(lines)):
            stripped = lines[idx].strip()
            if not stripped:
                continue
            if stripped.startswith("|") and stripped.endswith("|"):
                table_start = idx
                break
            # Allow free-text paragraph(s) before the table; keep scanning.
            if stripped.startswith("## "):
                # Hit the next section without finding a table.
                return []

        if table_start is None:
            return []

        # Walk the contiguous run of |...| rows.
        table_lines: list[str] = []
        for idx in range(table_start, len(lines)):
            stripped = lines[idx].strip()
            if stripped.startswith("|") and stripped.endswith("|"):
                table_lines.append(stripped)
                continue
            break

        if len(table_lines) < 2:
            return []

        header_cells = [cell.strip() for cell in table_lines[0].strip("|").split("|")]
        if [cell for cell in header_cells if cell] != ["Check", "Status", "Notes"]:
            return []

        data_rows: list[list[str]] = []
        # table_lines[0] = header, table_lines[1] = separator (---|---|---).
        for row in table_lines[2:]:
            cells = [cell.strip() for cell in row.strip("|").split("|")]
            data_rows.append(cells)
        return data_rows

    def test_canonical_closeout_summary_body_has_heading_columns_and_rows(self):
        body = self.CANONICAL_CLOSEOUT_SUMMARY_BODY
        self.assertIn("\n## Closeout Summary\n", body)
        rows = self._extract_closeout_summary_table_rows(body)
        self.assertGreater(len(rows), 0)
        # Every data row must have the 3 canonical columns.
        for row in rows:
            self.assertEqual(len(row), 3, row)
        # And the canonical fixture must include real status tokens.
        statuses = {row[1] for row in rows}
        self.assertTrue(statuses.issubset({"PASS", "WARN", "FAIL"}), statuses)

    def test_missing_closeout_summary_heading_yields_no_rows(self):
        rows = self._extract_closeout_summary_table_rows(self.HEADING_MISSING_BODY)
        self.assertEqual(rows, [])

    def test_renamed_closeout_summary_columns_yield_no_rows(self):
        rows = self._extract_closeout_summary_table_rows(self.COLUMNS_RENAMED_BODY)
        self.assertEqual(rows, [])

    def test_empty_closeout_summary_table_yields_no_rows(self):
        rows = self._extract_closeout_summary_table_rows(self.EMPTY_TABLE_BODY)
        self.assertEqual(rows, [])

    def test_loop6_pr_body_draft_satisfies_closeout_summary_shape(self):
        if not self.LOOP6_PR_BODY_PATH.exists():
            self.skipTest(f"loop-6 PR body draft not found at {self.LOOP6_PR_BODY_PATH}")
        body = self.LOOP6_PR_BODY_PATH.read_text(encoding="utf-8")
        self.assertIn("\n## Closeout Summary\n", body)
        rows = self._extract_closeout_summary_table_rows(body)
        # The L6 draft pulled the 22-row Spark closeout manifest snapshot.
        self.assertGreaterEqual(len(rows), 1)
        for row in rows:
            self.assertEqual(len(row), 3, row)
        statuses = {row[1] for row in rows}
        self.assertTrue(
            statuses.issubset({"PASS", "WARN", "FAIL"}),
            f"unexpected status tokens in loop-6 draft: {statuses}",
        )


if __name__ == "__main__":
    unittest.main()
