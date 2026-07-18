import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "agent-dispatch-prompt-lint.py"


def load_module():
    spec = importlib.util.spec_from_file_location("agent_dispatch_prompt_lint", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


prompt_lint = load_module()


class AgentDispatchPromptLintTest(unittest.TestCase):
    def result_for(self, text, rule, workspace=None):
        results = prompt_lint.lint(text, workspace=workspace)
        matches = [result for result in results if result.rule == rule]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def write_receipt(self, ws):
        receipt_dir = ws / ".auditooor"
        receipt_dir.mkdir(parents=True)
        receipt = {
            "schema": "auditooor.memory_context_receipt.v1",
            "workspace": ws.name,
            "workspace_path": str(ws),
            "generated_at": "2026-05-12T00:00:00Z",
            "loaded_contexts": [
                {
                    "requirement_id": "dispatch-context",
                    "context_kind": "dispatch",
                    "tool": "vault_dispatch_context",
                    "context_pack_id": "auditooor.vault_context_pack.v1:dispatch:abcdef0123456789",
                    "context_pack_hash": "a" * 64,
                    "pack_path": str(receipt_dir / "pack.json"),
                    "loaded_at": "2026-05-12T00:00:01Z",
                    "status": "loaded",
                }
            ],
            "summary": {
                "required_count": 1,
                "loaded_count": 1,
                "missing_count": 0,
                "stale_count": 0,
                "strict_ready": True,
            },
        }
        (receipt_dir / "memory_context_receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return receipt

    def test_missing_truth_inference_without_evidence_fails(self):
        prompt = """
        task.type: next-loop-dispatch
        ## Acceptance
        - Infer the missing protocol rubric proof and fill the source field.
        - Deliverable: `docs/example.md`
        - Self-test mandatory.
        - Branch: `next-loop-example`
        """

        result = self.result_for(prompt, "R8_missing_truth_evidence")

        self.assertEqual(result.status, prompt_lint.FAIL)
        self.assertIn("without requiring direct evidence", result.message)

    def test_missing_truth_inference_with_source_evidence_passes(self):
        prompt = """
        task.type: next-loop-dispatch
        ## Acceptance
        - Infer the missing protocol rubric proof only from provided production source.
        - Include source citations with file:line or KG refs such as KG-20260505-001.
        - Deliverable: `docs/example.md`
        - Self-test mandatory.
        - Branch: `next-loop-example`
        """

        result = self.result_for(prompt, "R8_missing_truth_evidence")

        self.assertEqual(result.status, prompt_lint.PASS)

    def test_negated_missing_truth_inference_passes(self):
        prompt = """
        task.type: next-loop-dispatch
        ## Acceptance
        - Do not infer the missing protocol proof; leave TODO_OPERATOR.
        - Deliverable: `docs/example.md`
        - Self-test mandatory.
        - Branch: `next-loop-example`
        """

        result = self.result_for(prompt, "R8_missing_truth_evidence")

        self.assertEqual(result.status, prompt_lint.PASS)

    def test_source_refs_count_as_missing_truth_evidence(self):
        prompt = """
        task.type: next-loop-dispatch
        ## Acceptance
        - Infer the missing protocol proof only from source_refs.
        - Deliverable: `docs/example.md`
        - Self-test mandatory.
        - Branch: `next-loop-example`
        """

        result = self.result_for(prompt, "R8_missing_truth_evidence")

        self.assertEqual(result.status, prompt_lint.PASS)

    def test_untrusted_source_section_does_not_trigger_missing_truth_rule(self):
        prompt = """
        task.type: next-loop-dispatch
        ### Finding Content
        The report says identify missing protocol proof from old notes.

        ## Acceptance
        - Summarize the finding without filling unknown source truth.
        - Deliverable: `docs/example.md`
        - Self-test mandatory.
        - Branch: `next-loop-example`
        """

        result = self.result_for(prompt, "R8_missing_truth_evidence")

        self.assertEqual(result.status, prompt_lint.PASS)

    def test_mandatory_context_pack_is_global_missing_truth_anchor(self):
        prompt = """
        task.type: next-loop-dispatch
        ## Mandatory Context Pack
        - context_pack_path: `obsidian-vault/dispatch/context-packs/g8.dispatch.json`
        - source_refs:
          - `docs/CURRENT_STATE.md`
        - knowledge_gap_refs:
          - `KG-20260505-001`

        ## Acceptance
        - Infer the missing protocol proof from the mandatory context pack.
        - Deliverable: `docs/example.md`
        - Self-test mandatory.
        - Branch: `next-loop-example`
        """

        result = self.result_for(prompt, "R8_missing_truth_evidence")

        self.assertEqual(result.status, prompt_lint.PASS)

    def test_workspace_receipt_without_prompt_evidence_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self.write_receipt(ws)
            prompt = """
            task.type: next-loop-dispatch
            ## Acceptance
            - Deliverable: `docs/example.md`
            - Self-test mandatory.
            - Branch: `next-loop-example`
            """

            result = self.result_for(prompt, "R9_mcp_receipt_evidence", workspace=ws)

            self.assertEqual(result.status, prompt_lint.FAIL)
            self.assertIn("does not mention", result.message)

    def test_workspace_receipt_with_loaded_context_evidence_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            receipt = self.write_receipt(ws)
            loaded = receipt["loaded_contexts"][0]
            prompt = f"""
            task.type: next-loop-dispatch
            ## Workspace MCP Receipt
            - workspace_receipt: `{ws}/.auditooor/memory_context_receipt.json`
            - context_pack_hash: `{loaded["context_pack_hash"]}`

            ## Acceptance
            - Deliverable: `docs/example.md`
            - Self-test mandatory.
            - Branch: `next-loop-example`
            """

            result = self.result_for(prompt, "R9_mcp_receipt_evidence", workspace=ws)

            self.assertEqual(result.status, prompt_lint.PASS)

    def test_canonical_worker_packet_receipt_passes_r9_and_r10(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            receipt = self.write_receipt(ws)
            loaded = receipt["loaded_contexts"][0]
            prompt = f"""
            task.type: source-extract
            worker_packet_path: `{ws}/.auditooor/worker_packets/canonical.json`
            schema: auditooor.v3_worker_packet.v1
            packet_hash: {"b" * 64}
            source receipt: `.auditooor/memory_context_receipt.json`
            context_pack_id: {loaded["context_pack_id"]}
            context_pack_hash: {loaded["context_pack_hash"]}

            ## Acceptance
            - Review detector hits and produce a proof lane.
            - Deliverable: `reports/example.md`
            - Self-test mandatory.
            """

            r9 = self.result_for(prompt, "R9_mcp_receipt_evidence", workspace=ws)
            r10 = self.result_for(prompt, "R10_audit_agent_start_packet", workspace=ws)

            self.assertEqual(r9.status, prompt_lint.PASS)
            self.assertEqual(r10.status, prompt_lint.PASS)

    def test_workspace_receipt_with_mcp_evidence_sidecar_passes_r9(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            receipt = self.write_receipt(ws)
            loaded = receipt["loaded_contexts"][0]
            prompt = f"""
            task.type: source-extract
            receipt_path: `{ws}/.auditooor/worker_packets/canonical.mcp_evidence_receipt.json`
            schema: auditooor.mcp_evidence_receipt.v1
            context_pack_id: {loaded["context_pack_id"]}
            context_pack_hash: {loaded["context_pack_hash"]}

            ## Acceptance
            - Review detector hits and produce a proof lane.
            - Deliverable: `reports/example.md`
            - Self-test mandatory.
            """

            result = self.result_for(prompt, "R9_mcp_receipt_evidence", workspace=ws)

            self.assertEqual(result.status, prompt_lint.PASS)

    def test_audit_prompt_with_mcp_evidence_sidecar_passes_r10(self):
        prompt = f"""
        task.type: source-extract
        receipt_path: `.auditooor/worker_packets/canonical.mcp_evidence_receipt.json`
        schema: auditooor.mcp_evidence_receipt.v1
        context_pack_id: auditooor.vault_hacker_brief_for_lane.v1:test
        context_pack_hash: {"a" * 64}

        ## Acceptance
        - Review detector hits and produce a proof lane.
        - Deliverable: `reports/example.md`
        - Self-test mandatory.
        """

        result = self.result_for(prompt, "R10_audit_agent_start_packet")

        self.assertEqual(result.status, prompt_lint.PASS)

    def test_mcp_evidence_sidecar_without_context_hash_fails_r10(self):
        prompt = """
        task.type: source-extract
        receipt_path: `.auditooor/worker_packets/canonical.mcp_evidence_receipt.json`
        schema: auditooor.mcp_evidence_receipt.v1
        context_pack_id: auditooor.vault_hacker_brief_for_lane.v1:test

        ## Acceptance
        - Review detector hits and produce a proof lane.
        - Deliverable: `reports/example.md`
        - Self-test mandatory.
        """

        result = self.result_for(prompt, "R10_audit_agent_start_packet")

        self.assertEqual(result.status, prompt_lint.FAIL)

    def test_audit_prompt_without_start_packet_fails(self):
        prompt = """
        task.type: source-extract
        ## Acceptance
        - Review detector hits and produce a proof lane.
        - Deliverable: `reports/example.md`
        - Self-test mandatory.
        """

        result = self.result_for(prompt, "R10_audit_agent_start_packet")

        self.assertEqual(result.status, prompt_lint.FAIL)
        self.assertIn("MCP/rules/hackermind", result.message)

    def test_audit_prompt_with_callable_names_only_fails(self):
        prompt = """
        task.type: source-extract
        Use vault_resume_context and vault_dispatch_context plus hacker kill_rubric.

        ## Acceptance
        - Review detector hits and produce a proof lane.
        - Deliverable: `reports/example.md`
        - Self-test mandatory.
        """

        result = self.result_for(prompt, "R10_audit_agent_start_packet")

        self.assertEqual(result.status, prompt_lint.FAIL)
        self.assertIn("MCP/rules/hackermind", result.message)

    def test_audit_prompt_with_start_card_passes(self):
        prompt = """
        task.type: source-extract
        ## Required Start Packet
        Read `docs/MCP_AUDIT_AGENT_START.md` before source work.

        ## Acceptance
        - Review detector hits and produce a proof lane.
        - Deliverable: `reports/example.md`
        - Self-test mandatory.
        """

        result = self.result_for(prompt, "R10_audit_agent_start_packet")

        self.assertEqual(result.status, prompt_lint.PASS)

    def test_audit_prompt_with_equivalent_rule_packet_passes(self):
        prompt = """
        task.type: paste-ready-review
        ## Memory Context
        - context_pack_id: auditooor.vault_context_pack.v1:dispatch:abc
        - context_pack_hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

        ## Rules And Hacker Context
        - pre-submit gates: L27, R24, R30.
        - hacker pulls: vault_engage_report_context, vault_function_mindset,
          kill_rubric, dupe/rejection, originality.

        ## Acceptance
        - Review the finding and proof artifact.
        - Deliverable: `reports/example.md`
        - Self-test mandatory.
        """

        result = self.result_for(prompt, "R10_audit_agent_start_packet")

        self.assertEqual(result.status, prompt_lint.PASS)

    def test_empty_candidate_rows_fail_closed(self):
        prompt = """
        task.type: source-extraction
        ## Acceptance
        - Review the real-world recall queue rows and return JSON.
        - Deliverable: `agent_outputs/provider_packets/example/out.md`
        - Self-test mandatory.

        Actual queue rows for admin-bypass:
        []
        """

        result = self.result_for(prompt, "R11_empty_candidate_packet")

        self.assertEqual(result.status, prompt_lint.FAIL)
        self.assertIn("empty candidate/queue row set", result.message)

    def test_nonempty_candidate_rows_pass(self):
        prompt = """
        task.type: source-extraction
        ## Acceptance
        - Review the real-world recall queue rows and return JSON.
        - Deliverable: `agent_outputs/provider_packets/example/out.md`
        - Self-test mandatory.

        Actual queue rows for admin-bypass:
        [{"queue_id": "rwrq-admin-bypass-1"}]
        """

        result = self.result_for(prompt, "R11_empty_candidate_packet")

        self.assertEqual(result.status, prompt_lint.PASS)

    def test_prompt_without_candidate_packet_passes_empty_candidate_rule(self):
        prompt = """
        task.type: docs-plan
        ## Acceptance
        - Summarize provider calibration.
        - Deliverable: `reports/provider.md`
        - Self-test mandatory.
        """

        result = self.result_for(prompt, "R11_empty_candidate_packet")

        self.assertEqual(result.status, prompt_lint.PASS)


if __name__ == "__main__":
    unittest.main()
