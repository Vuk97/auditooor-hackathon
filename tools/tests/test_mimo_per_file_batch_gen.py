"""Tests for mimo-per-file-batch-gen reweight sampling."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "mimo-per-file-batch-gen.py"
HARNESS_TOOL = ROOT / "tools" / "mimo-harness-batch-gen.py"


def load_module():
    spec = importlib.util.spec_from_file_location("mimo_per_file_batch_gen", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load_module()


def load_harness_module():
    spec = importlib.util.spec_from_file_location("mimo_harness_batch_gen", HARNESS_TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


HARNESS = load_harness_module()


class TestMimoPerFileBatchGen(unittest.TestCase):
    def test_reweight_orders_questions_by_signal_score(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mimo-per-file-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "ws"
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "Vault.sol").write_text(
                "contract Vault { function withdraw() external {} }\n",
                encoding="utf-8",
            )
            hq = tmp / "hacker_questions.jsonl"
            questions = [
                {"question_id": "q-low", "question_text": "low", "attack_class_anchor": "dos"},
                {"question_id": "q-high", "question_text": "high", "attack_class_anchor": "theft"},
                {"question_id": "q-mid", "question_text": "mid", "attack_class_anchor": "freeze"},
            ]
            hq.write_text("".join(json.dumps(q) + "\n" for q in questions), encoding="utf-8")
            reweight = tmp / "hacker_q_reweight_2026-05-28.jsonl"
            reweight.write_text(
                "\n".join([
                    json.dumps({"question_id": "q-low", "signal_score": -5, "signal_class": "LOW"}),
                    json.dumps({"question_id": "q-high", "signal_score": 10, "signal_class": "HIGH"}),
                    json.dumps({"question_id": "q-mid", "signal_score": 2, "signal_class": "MED"}),
                ]) + "\n",
                encoding="utf-8",
            )
            out = tmp / "tasks.jsonl"
            rc = MOD.main([
                "--workspace", "ws",
                "--workspace-path", str(ws),
                "--hacker-q-corpus", str(hq),
                "--dead-ends", str(tmp / "missing_dead_ends.jsonl"),
                "--output", str(out),
                "--max-questions-per-file", "3",
                "--reweight-path", str(reweight),
            ])
            self.assertEqual(rc, 0)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([r["source_question_id"] for r in rows], ["q-high", "q-mid", "q-low"])
            self.assertEqual(rows[0]["hacker_q_reweight"]["signal_score"], 10)

    def test_per_file_prompt_has_agi_context_blocks_and_metadata(self) -> None:
        old_fetch = MOD.fetch_mcp_context

        def fake_fetch(workspace_path, callable_name, extra_args, cap=1200):
            return {
                "callable": callable_name,
                "status": "ok",
                "reason": "",
                "context_pack_id": f"pack-{callable_name}",
                "text": f"{callable_name} context for {extra_args}",
            }

        MOD.fetch_mcp_context = fake_fetch
        try:
            with tempfile.TemporaryDirectory(prefix="mimo-per-file-context-") as tmp_raw:
                tmp = Path(tmp_raw)
                ws = tmp / "ws"
                src = ws / "src"
                src.mkdir(parents=True)
                (src / "Vault.sol").write_text(
                    "\n".join([
                        "contract Vault {",
                        "  mapping(address => uint256) public bal;",
                        "  function withdraw(uint256 amount) external {",
                        "    bal[msg.sender] -= amount;",
                        "    payable(msg.sender).transfer(amount);",
                        "  }",
                        "}",
                    ]) + "\n",
                    encoding="utf-8",
                )
                hq = tmp / "hacker_questions.jsonl"
                hq.write_text(json.dumps({
                    "question_id": "q-theft",
                    "question_text": "Can withdraw reorder accounting and external transfer?",
                    "attack_class_anchor": "theft",
                }) + "\n", encoding="utf-8")
                reweight = tmp / "hacker_q_reweight_2026-05-28.jsonl"
                reweight.write_text(json.dumps({
                    "question_id": "q-theft",
                    "signal_score": 12,
                    "signal_class": "HIGH",
                    "yes_count": 3,
                    "maybe_count": 1,
                    "no_count": 0,
                }) + "\n", encoding="utf-8")
                dead = tmp / "dead.jsonl"
                dead.write_text(json.dumps({
                    "workspace": "ws",
                    "file": "Other.sol",
                    "attack_class": "theft",
                    "exact_verdict": "do not retry old Vault withdraw false positive",
                }) + "\n", encoding="utf-8")
                out = tmp / "tasks.jsonl"
                rc = MOD.main([
                    "--workspace", "ws",
                    "--workspace-path", str(ws),
                    "--hacker-q-corpus", str(hq),
                    "--dead-ends", str(dead),
                    "--output", str(out),
                    "--max-questions-per-file", "1",
                    "--reweight-path", str(reweight),
                ])
                self.assertEqual(rc, 0)
                row = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
                prompt = row["prompt"]
                self.assertIn("=== AGI-GRADE CONTEXT FEED", prompt)
                self.assertIn("=== FUNCTION SIGNATURE SHAPE AND LOCAL FINGERPRINT ===", prompt)
                self.assertIn("withdraw(uint256 amount)", prompt)
                self.assertIn("=== KNOWN DEAD-ENDS - DO NOT RE-INVESTIGATE ===", prompt)
                self.assertIn("exact_verdict", prompt)
                self.assertIn("=== HACKER-Q REWEIGHT SCORE ===", prompt)
                self.assertIn("vault_attack_class_evidence_v3", prompt)
                self.assertIn("vault_anti_pattern_corpus", prompt)
                self.assertIn("vault_exploit_narratives_synthesized", prompt)
                meta = row["mimo_context_feed"]
                self.assertEqual(meta["attack_class"], "theft")
                self.assertEqual(meta["language"], "solidity")
                self.assertEqual(meta["known_dead_end_matches"], 1)
                self.assertTrue(meta["has_reweight_record"])
                self.assertEqual(meta["function_signature_count"], 1)
                self.assertRegex(meta["context_sha256"], r"^[0-9a-f]{64}$")
                self.assertIn("attack_class_evidence", meta["context_fields"])
                self.assertIn("known_dead_ends_verbatim", meta["context_fields"])
                self.assertEqual(row["hacker_q_reweight"]["signal_score"], 12)
        finally:
            MOD.fetch_mcp_context = old_fetch

    def test_scan_root_overrides_workspace_exclusions_for_external_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mimo-scan-root-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "thegraph"
            source_root = ws / "external" / "contracts" / "packages"
            source_root.mkdir(parents=True)
            (source_root / "Subgraph.sol").write_text(
                "contract Subgraph { function collect() external {} }\n",
                encoding="utf-8",
            )
            (ws / "poc-tests").mkdir(parents=True)
            (ws / "poc-tests" / "Noise.sol").write_text(
                "contract Noise { function ignore() external {} }\n",
                encoding="utf-8",
            )
            hq = tmp / "hacker_questions.jsonl"
            hq.write_text(json.dumps({
                "question_id": "q-source",
                "question_text": "Can collect break accounting?",
                "attack_class_anchor": "theft",
            }) + "\n", encoding="utf-8")
            out = tmp / "tasks.jsonl"

            rc = MOD.main([
                "--workspace", "thegraph",
                "--workspace-path", str(ws),
                "--scan-root", "external/contracts/packages",
                "--hacker-q-corpus", str(hq),
                "--dead-ends", str(tmp / "missing_dead_ends.jsonl"),
                "--output", str(out),
                "--no-reweight",
                "--json",
            ])

            self.assertEqual(rc, 0)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["file_anchor"]["file_path"], "external/contracts/packages/Subgraph.sol")

    def test_scan_root_txt_is_honored_before_workspace_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mimo-scan-root-file-") as tmp_raw:
            tmp = Path(tmp_raw)
            ws = tmp / "thegraph"
            source_root = ws / "agent_outputs" / "codex-graph-prep-20260517" / "eu2_foundry_out"
            source_root.mkdir(parents=True)
            (source_root / "GraphPrep.sol").write_text(
                "contract GraphPrep { function settle() external {} }\n",
                encoding="utf-8",
            )
            (ws / ".auditooor").mkdir(parents=True)
            (ws / ".auditooor" / "scan_root.txt").write_text(
                "agent_outputs/codex-graph-prep-20260517/eu2_foundry_out\n",
                encoding="utf-8",
            )
            hq = tmp / "hacker_questions.jsonl"
            hq.write_text(json.dumps({
                "question_id": "q-prep",
                "question_text": "Can settle release funds?",
                "attack_class_anchor": "theft",
            }) + "\n", encoding="utf-8")
            out = tmp / "tasks.jsonl"

            rc = MOD.main([
                "--workspace", "thegraph",
                "--workspace-path", str(ws),
                "--hacker-q-corpus", str(hq),
                "--dead-ends", str(tmp / "missing_dead_ends.jsonl"),
                "--output", str(out),
                "--no-reweight",
            ])

            self.assertEqual(rc, 0)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(
                rows[0]["file_anchor"]["file_path"],
                "agent_outputs/codex-graph-prep-20260517/eu2_foundry_out/GraphPrep.sol",
            )

    def test_harness_prompt_has_per_item_context_and_reweight_metadata(self) -> None:
        old_fetch = HARNESS.fetch_mcp

        def fake_fetch(workspace_path, callable_name, extra_args, lane_id=None):
            return json.dumps({
                "callable": callable_name,
                "args": extra_args,
                "lane_id": lane_id,
            }, sort_keys=True)

        HARNESS.fetch_mcp = fake_fetch
        try:
            with tempfile.TemporaryDirectory(prefix="mimo-harness-context-") as tmp_raw:
                tmp = Path(tmp_raw)
                ws = tmp / "ws"
                ws.mkdir()
                (ws / "SEVERITY.md").write_text("HIGH: direct loss of funds\n", encoding="utf-8")
                question_text = (
                    "Investigate whether the function can release protocol custody "
                    "before accounting is finalized and whether that produces a "
                    "direct loss of funds for another user."
                )
                qpath = tmp / "questions.jsonl"
                qpath.write_text(json.dumps({
                    "record_id": "q-high",
                    "statement": question_text,
                    "attack_class_anchor": "theft",
                    "target_language": "solidity",
                    "function_signature": "function withdraw(uint256 amount) external",
                }) + "\n", encoding="utf-8")
                reweight = tmp / "hacker_q_reweight_2026-05-28.jsonl"
                reweight.write_text(json.dumps({
                    "question_id": "q-high",
                    "signal_score": 9,
                    "signal_class": "HIGH",
                    "yes_count": 2,
                    "maybe_count": 0,
                    "no_count": 0,
                }) + "\n", encoding="utf-8")
                dead = tmp / "dead.jsonl"
                dead.write_text(json.dumps({
                    "workspace": "ws",
                    "attack_class": "theft",
                    "verbatim_stop_reason": "known historical dead end",
                }) + "\n", encoding="utf-8")
                out = tmp / "tasks.jsonl"
                rc = HARNESS.main([
                    "--workspace-name", "ws",
                    "--workspace-path", str(ws),
                    "--question-corpus", str(qpath),
                    "--num-questions", "1",
                    "--lane-id", "lane-p4",
                    "--output", str(out),
                    "--dead-ends", str(dead),
                    "--reweight-path", str(reweight),
                ])
                self.assertEqual(rc, 0)
                row = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
                prompt = row["prompt"]
                self.assertIn("=== AGI-GRADE TASK CONTEXT", prompt)
                self.assertIn("=== FUNCTION SIGNATURE SHAPE ===", prompt)
                self.assertIn("vault_function_signature_shape", prompt)
                self.assertIn("=== KNOWN DEAD-ENDS - DO NOT RE-INVESTIGATE ===", prompt)
                self.assertIn("verbatim_stop_reason", prompt)
                self.assertIn("=== HACKER-Q REWEIGHT SCORE ===", prompt)
                self.assertIn("vault_attack_class_evidence_v3", prompt)
                self.assertIn("vault_anti_pattern_corpus", prompt)
                self.assertIn("vault_exploit_narratives_synthesized", prompt)
                self.assertIn("vault_global_chain_template_match", prompt)
                self.assertIn("vault_mimo_corpus_intelligence", prompt)
                meta = row["mimo_context_feed"]
                self.assertEqual(meta["attack_class"], "theft")
                self.assertTrue(meta["function_signature_present"])
                self.assertTrue(meta["has_reweight_record"])
                self.assertEqual(meta["known_dead_end_matches"], 1)
                self.assertIn("vault_function_signature_shape", meta["mcp_calls"])
                self.assertIn("global_chain_templates", meta["context_fields"])
                self.assertIn("hacker_q_reweight_score", meta["context_fields"])
                self.assertRegex(meta["context_sha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(row["hacker_q_reweight"]["signal_score"], 9)
        finally:
            HARNESS.fetch_mcp = old_fetch


if __name__ == "__main__":
    unittest.main()
