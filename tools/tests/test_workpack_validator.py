from __future__ import annotations

import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "workpack-validator.py"


def _load_validator():
    spec = importlib.util.spec_from_file_location("workpack_validator", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load workpack-validator.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkpackValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = _load_validator()

    def _write(self, body: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "workpack.md"
        path.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
        return path

    def test_rejects_workpack_without_memory_context(self) -> None:
        path = self._write(
            """
            ## Changed files
            - tools/example.py

            ## Commands run
            - make audit WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            rerun proof
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn("Memory context used", result["missing_fields"])

    def test_accepts_workpack_with_vault_mcp_context_pack(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":8}'
            - make audit WS=/tmp/ws
            - DEEP_PROFILE=all make audit-deep WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            SUBMIT

            ## Known limitation
            none

            ## Next blocker
            none

            Chain/escalation attempt:
            - Attempted to chain this primitive into the strongest in-scope High impact and documented why it did not hold.

            Impact(s):
            - selected_impact: Temporary freezing of user funds
            - severity: Medium
            - likelihood: Medium
            - impact: Medium

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])

    def test_final_paste_handoff_requires_memory_trace_or_receipt_check(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - make audit WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            operator duplicate review before final paste handoff

            Final paste handoff:
            - Ready to brief the next agent for final paste once the duplicate check returns clean.

            ## Memory context
            vault_resume_context was consulted.
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "Final paste/HM handoff workpack includes `context_pack_id`, "
            "`context_pack_hash`, and `source_refs`, or the strict "
            "`memory-context-load.py --check --strict --require-proof` command",
            result["missing_fields"],
        )

    def test_final_paste_handoff_accepts_strict_receipt_check_command(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - make audit WS=/tmp/ws
            - python3 tools/memory-context-load.py --workspace /tmp/ws --from-requirements --check --strict --require-proof --json

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            operator duplicate review before final paste handoff

            Final paste handoff:
            - Ready to brief the next agent for final paste once the duplicate check returns clean.

            ## Memory context
            MCP unavailable; strict receipt check command is recorded above.
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])

    def test_hm_handoff_accepts_explicit_context_pack_trace(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - make audit WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            operator review before HM submission handoff

            HM submission handoff:
            - Package the exact memory trace before asking another agent to verify the final wording.

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - workspace:submissions/final_cantina_paste/finding.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])

    def test_submit_workpack_requires_audit_and_deep_evidence(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":8}'

            ## Output
            PASS

            ## Disposition
            SUBMIT

            ## Known limitation
            none

            ## Next blocker
            none

            Chain/escalation attempt:
            - Attempted to escalate to the strongest in-scope High impact; blocker: no broader listed-impact sentence survived the negative control.

            Impact(s):
            - selected_impact: Temporary freezing of user funds
            - severity: Medium
            - likelihood: Medium
            - impact: Medium

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "SUBMIT workpack includes `make audit WS=...` evidence",
            result["missing_fields"],
        )
        self.assertIn(
            "SUBMIT workpack includes `make audit-deep WS=...` evidence "
            "or an explicit audit-deep waiver/blocker",
            result["missing_fields"],
        )

    def test_workflow_completion_claim_requires_audit_and_deep_evidence(self) -> None:
        path = self._write(
            """
            ## Changed files
            - reports/audit_summary.md

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":8}'

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            Summary:
            - End-to-end audit workflow completed for this workspace.

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "End-to-end workflow completion claim includes both "
            "`make audit WS=...` and `make audit-deep WS=...` evidence, "
            "or an explicit blocker artifact",
            result["missing_fields"],
        )

    def test_complete_workpack_requires_artifact_path_or_no_artifact_reason(self) -> None:
        path = self._write(
            """
            ## Changed files
            - none

            ## Commands run
            - go test ./...

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            Status: complete

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "Complete workpack declares artifact paths or explicit NO_ARTIFACT reason",
            result["missing_fields"],
        )

    def test_complete_workpack_accepts_no_artifact_reason(self) -> None:
        path = self._write(
            """
            ## Changed files
            - none

            ## Commands run
            - go test ./...

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            Status: complete

            ## NO_ARTIFACT
            - No target source file changed; this is a closeout-only workpack.

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])

    def test_complete_workpack_requires_tests_or_logs_references(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws"}'

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            Status: complete

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "Complete workpack includes test command evidence or log references",
            result["missing_fields"],
        )

    def test_complete_workpack_requires_mcp_context_trace_or_receipt_check(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - go test ./tools/tests -run Workpack -v

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            Status: complete

            ## Memory context
            vault_resume_context was consulted.
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "Complete workpack includes MCP memory/context evidence via "
            "`context_pack_id`, `context_pack_hash`, and `source_refs`, "
            "or the strict "
            "`memory-context-load.py --check --strict --require-proof` command",
            result["missing_fields"],
        )

    def test_complete_workpack_accepts_strict_receipt_check_command(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - go test ./tools/tests -run Workpack -v
            - python3 tools/memory-context-load.py --workspace /tmp/ws --from-requirements --check --strict --require-proof --json

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            Status: complete

            ## Memory context
            Strict receipt verification command is recorded above.
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])

    def test_incomplete_workpack_is_not_forced_to_be_complete(self) -> None:
        path = self._write(
            """
            ## Changed files
            - none

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws"}'

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])

    def test_not_complete_result_is_not_treated_as_complete(self) -> None:
        path = self._write(
            """
            ## Changed files
            - none

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws"}'

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            Result: not complete

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])

    def test_workflow_completion_claim_accepts_audit_pair(self) -> None:
        path = self._write(
            """
            ## Changed files
            - reports/audit_summary.md

            ## Commands run
            - make audit WS=/tmp/ws
            - DEEP_PROFILE=all make audit-deep WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            Summary:
            - Full audit workflow completed for this workspace.

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])

    def test_workflow_completion_claim_accepts_explicit_blocker_artifact(self) -> None:
        path = self._write(
            """
            ## Changed files
            - reports/audit_summary.md
            - reports/workflow_blocker_2026-05-06.json

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":8}'

            ## Output
            BLOCKED

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            provision Go toolchain and rerun the audit pair

            Summary:
            - Canonical audit workflow completion is blocked by local toolchain setup.

            Workflow blocker artifact: reports/workflow_blocker_2026-05-06.json

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])

    def test_submit_workpack_requires_context_pack_id_hash_and_source_evidence(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - make audit WS=/tmp/ws
            - DEEP_PROFILE=all make audit-deep WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            SUBMIT

            ## Known limitation
            none

            ## Next blocker
            none

            Chain/escalation attempt:
            - Attempted to chain this primitive into the strongest in-scope High impact and recorded why it stayed Medium.

            Impact(s):
            - selected_impact: Temporary freezing of user funds
            - severity: Medium
            - likelihood: Medium
            - impact: Medium

            ## Memory context
            vault_resume_context was consulted.
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "SUBMIT workpack includes `context_pack_id: ...` MCP memory context",
            result["missing_fields"],
        )
        self.assertIn(
            "SUBMIT workpack includes `context_pack_hash: ...` MCP memory context",
            result["missing_fields"],
        )
        self.assertIn(
            "SUBMIT workpack includes source_refs evidence for MCP memory context",
            result["missing_fields"],
        )

    def test_submit_workpack_rejects_vault_call_without_source_refs(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":8}'
            - make audit WS=/tmp/ws
            - DEEP_PROFILE=all make audit-deep WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            SUBMIT

            ## Known limitation
            none

            ## Next blocker
            none

            Chain/escalation attempt:
            - Attempted to chain this primitive into the strongest in-scope High impact and documented why it did not hold.

            Impact(s):
            - selected_impact: Temporary freezing of user funds
            - severity: Medium
            - likelihood: Medium
            - impact: Medium

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "MCP-backed workflow claim includes `context_pack_id`, "
            "`context_pack_hash`, and `source_refs` evidence",
            result["missing_fields"],
        )
        self.assertIn(
            "SUBMIT workpack includes source_refs evidence for MCP memory context",
            result["missing_fields"],
        )

    def test_submit_workpack_rejects_blocked_readiness_markers(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - make audit WS=/tmp/ws
            - audit-deep blocked: platform toolchain unavailable in this sandbox

            ## Output
            PASS

            ## Disposition
            SUBMIT

            ## Known limitation
            none

            ## Next blocker
            none

            Chaining attempt notes:
            - Attempted to chain this primitive into the strongest in-scope High impact and recorded why it did not hold.

            Impact(s):
            - selected_impact: Temporary freezing of user funds
            - severity: Medium
            - likelihood: Medium
            - impact: Medium

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test

            Status: NOT_SUBMIT_READY because the PoC is EXECUTION_BLOCKED.
            listed_impact_proven=false
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "SUBMIT workpack has no NOT_SUBMIT_READY / EXECUTION_BLOCKED / "
            "listed_impact_proven=false marker",
            result["missing_fields"],
        )

    def test_submit_workpack_requires_chain_and_selector_evidence(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":8}'
            - make audit WS=/tmp/ws
            - DEEP_PROFILE=all make audit-deep WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            SUBMIT

            ## Known limitation
            none

            ## Next blocker
            none

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertFalse(result["passes"])
        self.assertIn(
            "SUBMIT workpack includes explicit chain/escalation attempt evidence",
            result["missing_fields"],
        )
        self.assertIn(
            "SUBMIT workpack includes platform selector evidence "
            "(`Impact(s)` or severity/likelihood/impact selector language)",
            result["missing_fields"],
        )

    def test_submit_workpack_accepts_chain_and_selector_evidence(self) -> None:
        path = self._write(
            """
            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":8}'
            - make audit WS=/tmp/ws
            - DEEP_PROFILE=all make audit-deep WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            SUBMIT

            ## Known limitation
            none

            ## Next blocker
            none

            Escalation attempt notes:
            - Attempted to escalate this primitive into the strongest in-scope High impact and recorded why it stayed Medium.

            Severity: Medium
            Likelihood: Medium
            Impact: Medium

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])


class SeverityRubricVerbatimGrepTest(unittest.TestCase):
    """L19 rubric-discipline gate (codifies CLAUDE.md L17 + L18 lessons).

    These tests cover the `severity_rubric_verbatim_grep` check added to
    `tools/workpack-validator.py`. Each test stages a fake rubric tree under
    a tempdir and points the gate at it via the `rubric_root` parameter.
    """

    SEVERITY_MD_BODY = (
        "# Severity rubric — Spark (Lightspark) Immunefi bounty\n"
        "\n"
        "## Rubric (verbatim from bounty page)\n"
        "\n"
        "### Critical (Blockchain/DLT)\n"
        "\n"
        "| ID | Listed-impact sentence (verbatim) | Reward |\n"
        "|---|---|---|\n"
        "| CRIT-1 | Direct loss of funds | cap |\n"
        "| CRIT-2 | Permanent freezing of funds (fix requires hardfork) | flat |\n"
        "\n"
        "Listed-impact sentences (verbatim, bullet form for rubric grounding):\n"
        "\n"
        "- Direct loss of funds\n"
        "- Permanent freezing of funds (fix requires hardfork)\n"
        "\n"
        "### High (Blockchain/DLT)\n"
        "\n"
        "Listed-impact sentences (verbatim, bullet form for rubric grounding):\n"
        "\n"
        "- RPC API crash affecting projects with greater than or equal to 25%"
        " of the market capitalization on top of the respective layer"
        " (excluding DoS-related attack vector)\n"
        "\n"
        "### Low (Blockchain/DLT)\n"
        "\n"
        "Listed-impact sentences (verbatim, bullet form for rubric grounding):\n"
        "\n"
        "- Contract fails to deliver promised returns, but doesn't lose value\n"
    )

    def setUp(self) -> None:
        self.validator = _load_validator()
        self.rubric_root = Path(tempfile.mkdtemp(prefix="rubric_root_"))
        self.addCleanup(self._cleanup_rubric_root)
        spark_dir = self.rubric_root / "spark"
        spark_dir.mkdir()
        (spark_dir / "SEVERITY.md").write_text(
            self.SEVERITY_MD_BODY, encoding="utf-8"
        )

    def _cleanup_rubric_root(self) -> None:
        import shutil

        shutil.rmtree(self.rubric_root, ignore_errors=True)

    def _write(self, body: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "workpack.md"
        path.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
        return path

    def test_passes_critical_with_verbatim_listed_impact_sentence(self) -> None:
        """LEAD 1 / LEAD H-D shape: Severity: Critical + verbatim impact in body."""
        path = self._write(
            """
            # Direct loss of funds in Spark cooperative-exit flow

            Status: ready to file
            Severity: Critical
            Target: github.com/buildonspark/spark at commit `e8311d2`

            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - python3 tools/vault-mcp-server.py --call vault_resume_context --args '{"workspace_path":"/tmp/ws","limit":8}'
            - make audit WS=/tmp/ws
            - DEEP_PROFILE=all make audit-deep WS=/tmp/ws

            ## Output
            PASS

            ## Disposition
            SUBMIT

            ## Known limitation
            none

            ## Next blocker
            none

            Chain/escalation attempt:
            - Attempted to escalate to the strongest in-scope High; recorded blocker.

            Impact(s):
            - selected_impact: Direct loss of funds
            - severity: Critical
            - likelihood: High
            - impact: Critical

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - workspace:submissions/staging/finding.md
            """
        )

        result = self.validator.validate_workpack(path, rubric_root=self.rubric_root)

        self.assertTrue(result["passes"], result)
        self.assertEqual(result["missing_fields"], [])
        names = [r["name"] for r in result["conditional_results"]]
        self.assertIn("severity_rubric_verbatim_grep", names)
        rubric = next(r for r in result["conditional_results"] if r["name"] == "severity_rubric_verbatim_grep")
        self.assertTrue(rubric["present"], rubric)

    def test_fails_when_severity_does_not_match_any_rubric_row(self) -> None:
        """LEAD COMMIT-RESUME shape: severity claim is `Critical` but the
        only verbatim-supported rubric rows are `Direct loss of funds` and
        `Permanent freezing of funds (fix requires hardfork)`, neither of
        which appear in the body — so the gate must fail."""
        path = self._write(
            """
            # Coordinator restart permafreezes Spark transfer

            Status: HOLD
            Severity: Critical
            Target: github.com/buildonspark/spark at commit `e8311d2`

            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - go test ./...

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            rubric mismatch — no listed-impact row matches state-machine permafreeze

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - workspace:submissions/staging/finding.md
            """
        )

        result = self.validator.validate_workpack(path, rubric_root=self.rubric_root)

        self.assertFalse(result["passes"])
        rubric = next(
            r for r in result["conditional_results"]
            if r["name"] == "severity_rubric_verbatim_grep"
        )
        self.assertFalse(rubric["present"])
        joined = " ".join(rubric.get("failure_reasons") or [])
        self.assertIn("rubric-mismatch", joined.lower())

    def test_fails_when_trigger_is_oos_attack_vector(self) -> None:
        """L18 AAF M14-trap: PoC supports the consequence claim but the
        trigger maps to OOS (honest-SO-crash). The gate must surface this
        even when the rubric row text would otherwise verbatim-match."""
        path = self._write(
            """
            # Permafreeze on coordinator restart

            Status: DROPPED — NOT FILEABLE under Spark Immunefi rubric
            Severity: Critical
            Target: github.com/buildonspark/spark at commit `e8311d2`

            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - go test ./...

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            attacker-induced trigger NOT identified — bug's TRIGGER is honest-SO-crash-via-natural-causes.
            Direct loss of funds claim cannot be supported because no in-scope attack vector triggers the bug.

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - workspace:submissions/staging/finding.md
            """
        )

        result = self.validator.validate_workpack(path, rubric_root=self.rubric_root)

        self.assertFalse(result["passes"])
        rubric = next(
            r for r in result["conditional_results"]
            if r["name"] == "severity_rubric_verbatim_grep"
        )
        self.assertFalse(rubric["present"])
        joined = " ".join(rubric.get("failure_reasons") or [])
        self.assertIn("trigger-vs-attack-vector M14-trap", joined)
        self.assertIn("rubric-discipline", joined)

    def test_passes_low_severity_with_verbatim_listed_impact_sentence(self) -> None:
        """Minor severity (Low) with verbatim row match — confirms the gate
        is severity-tier-agnostic and not over-fitted to Critical."""
        path = self._write(
            """
            # Spark contract delivery shortfall (informational)

            Status: ready to file
            Severity: Low
            Target: github.com/buildonspark/spark at commit `e8311d2`

            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - go test ./...

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            Listed-impact sentence: Contract fails to deliver promised returns, but doesn't lose value

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - workspace:submissions/staging/finding.md
            """
        )

        result = self.validator.validate_workpack(path, rubric_root=self.rubric_root)

        rubric = next(
            r for r in result["conditional_results"]
            if r["name"] == "severity_rubric_verbatim_grep"
        )
        self.assertTrue(rubric["present"], rubric)

    def test_skipped_when_engagement_marker_absent(self) -> None:
        """Generic workpacks without an engagement-resolvable Target line
        should not trigger the gate (no false-positive on infrastructure
        workpacks)."""
        path = self._write(
            """
            ## Changed files
            - tools/example.py

            ## Commands run
            - python3 -m unittest tools.tests.test_example

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - obsidian-vault/NEXT_LOOP.md
            """
        )

        result = self.validator.validate_workpack(path, rubric_root=self.rubric_root)
        names = [r["name"] for r in result["conditional_results"]]
        self.assertNotIn("severity_rubric_verbatim_grep", names)

    def test_skipped_when_rubric_file_missing_and_no_explicit_admissions(self) -> None:
        """If the engagement directory exists but SEVERITY.md is missing
        (engagement not yet onboarded to the gate), the gate must soft-skip
        rather than fail closed — provided no explicit M14-trap admissions
        are present."""
        # Remove the seeded SEVERITY.md so the rubric file lookup fails.
        (self.rubric_root / "spark" / "SEVERITY.md").unlink()

        path = self._write(
            """
            # Spark cooperative-exit finding

            Severity: Critical
            Target: github.com/buildonspark/spark at commit `e8311d2`

            ## Changed files
            - submissions/staging/finding.md

            ## Commands run
            - go test ./...

            ## Output
            PASS

            ## Disposition
            HOLD

            ## Known limitation
            none

            ## Next blocker
            none

            ## Memory context
            context_pack_id: auditooor.vault_context_pack.v1:resume:test
            context_pack_hash: test
            source_refs:
              - workspace:submissions/staging/finding.md
            """
        )

        result = self.validator.validate_workpack(path, rubric_root=self.rubric_root)
        names = [r["name"] for r in result["conditional_results"]]
        self.assertNotIn("severity_rubric_verbatim_grep", names)


if __name__ == "__main__":
    unittest.main()
