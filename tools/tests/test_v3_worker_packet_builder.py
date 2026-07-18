from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "v3-worker-packet-builder.py"


def load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("v3_worker_packet_builder", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = load_module()


class V3WorkerPacketBuilderTest(unittest.TestCase):
    def test_build_packet_hashes_source_files_and_context_ref_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            source = workspace / "src" / "target.sol"
            source.parent.mkdir()
            source.write_text("contract Target {}\n", encoding="utf-8")
            receipt_file = workspace / "reports" / "context.json"
            receipt_file.parent.mkdir()
            receipt_file.write_text('{"ok": true}\n', encoding="utf-8")

            packet = MOD.build_packet(
                workspace_path=workspace,
                packet_id="pkt-1",
                title="worker packet",
                mcp_context_refs=[
                    {
                        "context_pack_id": "ctx-1",
                        "context_pack_hash": "a" * 64,
                        "source_ref": "reports/context.json:1",
                    }
                ],
                source_files=["src/target.sol"],
                hacker_questions=["Can attacker bypass the guard?"],
                proof_obligations=["Show reachable production path."],
                verification_commands=["pytest tools/tests/test_v3_worker_packet_builder.py"],
                generated_at="2026-05-20T00:00:00+00:00",
            )

        receipts = packet["evidence_receipts"]["local_file_hashes"]
        by_name = {Path(row["resolved_path"]).name: row for row in receipts}
        self.assertEqual(packet["schema"], MOD.SCHEMA)
        self.assertTrue(packet["offline_only"])
        self.assertEqual(packet["offline_validation"]["status"], "ok")
        self.assertEqual(packet["evidence_receipts"]["receipt_count"], 2)
        self.assertEqual(
            by_name["target.sol"]["sha256"],
            hashlib.sha256(b"contract Target {}\n").hexdigest(),
        )
        self.assertEqual(
            by_name["context.json"]["sha256"],
            hashlib.sha256(b'{"ok": true}\n').hexdigest(),
        )
        self.assertRegex(packet["packet_hash"], r"^[0-9a-f]{64}$")

    def test_missing_file_gets_receipt_without_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            packet = MOD.build_packet(
                workspace_path=workspace,
                source_files=["missing.sol"],
                generated_at="2026-05-20T00:00:00+00:00",
            )

        receipts = packet["evidence_receipts"]["local_file_hashes"]
        self.assertEqual(len(receipts), 1)
        self.assertFalse(receipts[0]["exists"])
        self.assertNotIn("sha256", receipts[0])
        self.assertEqual(packet["evidence_receipts"]["missing_files"], [receipts[0]["resolved_path"]])

    def test_network_commands_are_blocked_for_offline_packet(self) -> None:
        packet = MOD.build_packet(
            workspace_path=ROOT,
            verification_commands=["forge test", "curl https://example.com/feed.json"],
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(packet["offline_validation"]["status"], "blocked")
        self.assertEqual(len(packet["offline_validation"]["blocked_commands"]), 1)
        self.assertIn("curl", packet["offline_validation"]["blocked_commands"][0]["command"])

    def test_high_packet_without_lesson_pack_receipt_is_blocked(self) -> None:
        packet = MOD.build_packet(
            workspace_path=ROOT,
            severity="High",
            mcp_context_refs=[],
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(packet["offline_validation"]["status"], "blocked")
        self.assertEqual(
            packet["offline_validation"]["lesson_pack_blockers"][0]["code"],
            "missing_lesson_pack_receipt",
        )

    def test_context_callable_name_alone_is_not_a_lesson_pack_receipt(self) -> None:
        packet = MOD.build_packet(
            workspace_path=ROOT,
            severity="Critical",
            mcp_context_refs=["vault_hacker_brief_for_lane_v3 should be used here"],
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(packet["offline_validation"]["status"], "blocked")
        self.assertEqual(
            packet["offline_validation"]["lesson_pack_blockers"][0]["code"],
            "missing_lesson_pack_receipt",
        )

    def test_high_packet_accepts_typed_no_lesson_pack_reason(self) -> None:
        packet = MOD.build_packet(
            workspace_path=ROOT,
            severity="High",
            no_lesson_pack_reason="NO_LESSON_PACK_REASON:no relevant local corpus rows for this fresh target",
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(packet["offline_validation"]["status"], "ok")
        self.assertEqual(packet["offline_validation"]["lesson_pack_blockers"], [])

    def test_high_packet_rejects_generic_context_pack_receipt(self) -> None:
        packet = MOD.build_packet(
            workspace_path=ROOT,
            severity="Critical",
            mcp_context_refs=[{"context_pack_id": "ctx-ok", "context_pack_hash": "c" * 64}],
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(packet["offline_validation"]["status"], "blocked")
        self.assertEqual(
            packet["offline_validation"]["lesson_pack_blockers"][0]["code"],
            "missing_lesson_pack_receipt",
        )
        self.assertEqual(packet["evidence_receipts"]["lesson_pack_receipt_count"], 0)

    def test_high_packet_accepts_lesson_pack_context_receipt(self) -> None:
        packet = MOD.build_packet(
            workspace_path=ROOT,
            severity="Critical",
            mcp_context_refs=[
                {
                    "tool": "vault_hacker_brief_for_lane",
                    "context_pack_id": "auditooor.vault_hacker_brief_for_lane.v1:test",
                    "context_pack_hash": "c" * 64,
                }
            ],
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(packet["offline_validation"]["status"], "ok")
        self.assertEqual(packet["offline_validation"]["lesson_pack_blockers"], [])
        self.assertEqual(packet["evidence_receipts"]["lesson_pack_receipt_count"], 1)

    def test_high_packet_accepts_mcp_evidence_receipt(self) -> None:
        packet = MOD.build_packet(
            workspace_path=ROOT,
            severity="High",
            mcp_context_refs=[
                {
                    "schema": "auditooor.mcp_evidence_receipt.v1",
                    "callable": "vault_route",
                    "context_pack_id": "auditooor.vault_route.v1:resume:test",
                    "context_pack_hash": "e" * 64,
                }
            ],
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(packet["offline_validation"]["status"], "ok")
        self.assertEqual(packet["evidence_receipts"]["lesson_pack_receipt_count"], 1)

    def test_high_packet_rejects_malformed_context_pack_hash(self) -> None:
        packet = MOD.build_packet(
            workspace_path=ROOT,
            severity="Critical",
            mcp_context_refs=[
                {
                    "tool": "vault_hacker_brief_for_lane",
                    "context_pack_id": "auditooor.vault_hacker_brief_for_lane.v1:test",
                    "context_pack_hash": "not-a-real-hash",
                }
            ],
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(packet["offline_validation"]["status"], "blocked")
        self.assertEqual(packet["evidence_receipts"]["lesson_pack_receipt_count"], 0)
        self.assertEqual(
            packet["offline_validation"]["lesson_pack_blockers"][0]["code"],
            "missing_lesson_pack_receipt",
        )

    def test_auto_workspace_receipts_collects_context_pack_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            aud = workspace / ".auditooor"
            aud.mkdir()
            receipt = aud / "memory_context_receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "loaded_contexts": [
                            {
                                "tool": "vault_hacker_brief_for_lane",
                                "requirement_id": "base.resume",
                                "context_pack_id": "auditooor.vault_hacker_brief_for_lane.v1:ctx-auto",
                                "context_pack_hash": "d" * 64,
                                "source_refs": ["vault://INDEX_active.md"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            packet = MOD.build_packet(
                workspace_path=workspace,
                severity="Critical",
                auto_workspace_receipts=True,
                generated_at="2026-05-20T00:00:00+00:00",
            )
            rendered = MOD.render_markdown(packet)

        self.assertEqual(packet["offline_validation"]["status"], "ok")
        self.assertEqual(packet["mcp_context_refs"][0]["context_pack_id"], "auditooor.vault_hacker_brief_for_lane.v1:ctx-auto")
        self.assertEqual(packet["mcp_context_refs"][0]["artifact_path"], ".auditooor/memory_context_receipt.json")
        self.assertIn("memory_context_receipt.json", rendered)
        self.assertIn("ctx-auto", rendered)

    def test_strict_cli_fails_for_blocked_packet(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ROOT),
                "--severity",
                "Critical",
                "--strict",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing_lesson_pack_receipt", result.stdout)

    def test_low_packet_does_not_require_lesson_pack_receipt(self) -> None:
        packet = MOD.build_packet(
            workspace_path=ROOT,
            severity="Low",
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(packet["offline_validation"]["status"], "ok")
        self.assertEqual(packet["offline_validation"]["lesson_pack_blockers"], [])

    def test_inputs_from_json_and_text_files_are_bounded_and_deduped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            context_file = workspace / "contexts.json"
            context_file.write_text(
                json.dumps(
                    [
                        {"context_pack_id": "ctx-a", "context_pack_hash": "a" * 64},
                        {"context_pack_id": "ctx-a", "context_pack_hash": "a" * 64},
                    ]
                ),
                encoding="utf-8",
            )
            commands_file = workspace / "commands.txt"
            commands_file.write_text("pytest one\npytest one\npytest two\n", encoding="utf-8")
            source_file_list = workspace / "sources.json"
            source_file_list.write_text(json.dumps({"files": ["a.sol", "a.sol", "b.sol"]}), encoding="utf-8")

            packet = MOD.build_packet(
                workspace_path=workspace,
                mcp_context_files=[context_file],
                source_files_files=[source_file_list],
                verification_command_files=[commands_file],
                generated_at="2026-05-20T00:00:00+00:00",
            )

        self.assertEqual(len(packet["mcp_context_refs"]), 1)
        self.assertEqual(packet["source_files"], ["a.sol", "b.sol"])
        self.assertEqual(packet["required_local_verification_commands"], ["pytest one", "pytest two"])
        self.assertEqual(packet["bounds"]["truncated"]["mcp_context_refs"], 1)

    def test_markdown_renders_obligations_commands_and_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            source = workspace / "src.go"
            source.write_text("package main\n", encoding="utf-8")
            packet = MOD.build_packet(
                workspace_path=workspace,
                packet_id="pkt-md",
                mcp_context_refs=[{"context_pack_id": "ctx-md", "context_pack_hash": "b" * 64}],
                source_files=["src.go"],
                hacker_questions=["What invariant breaks?"],
                proof_obligations=["Prove state transition."],
                verification_commands=["go test ./..."],
                generated_at="2026-05-20T00:00:00+00:00",
            )

        rendered = MOD.render_markdown(packet)

        self.assertIn("# V3 Worker Packet", rendered)
        self.assertIn("Packet ID: `pkt-md`", rendered)
        self.assertIn("ctx-md", rendered)
        self.assertIn("What invariant breaks?", rendered)
        self.assertIn("Prove state transition.", rendered)
        self.assertIn("`go test ./...`", rendered)
        self.assertIn("sha256", rendered)

    def test_cli_writes_json_and_markdown_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            source = workspace / "src.rs"
            source.write_text("fn main() {}\n", encoding="utf-8")
            out_json = workspace / "packet.json"
            out_md = workspace / "packet.md"

            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--packet-id",
                    "cli-pkt",
                    "--severity",
                    "Low",
                    "--source-file",
                    "src.rs",
                    "--verification-command",
                    "cargo test",
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            rendered = out_md.read_text(encoding="utf-8")

        self.assertEqual(payload["packet_id"], "cli-pkt")
        self.assertEqual(payload["offline_validation"]["status"], "ok")
        self.assertIn("cli-pkt", rendered)

    def test_cli_writes_mcp_evidence_receipt_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            source = workspace / "src.rs"
            source.write_text("fn main() {}\n", encoding="utf-8")
            out_json = workspace / "packet.json"
            out_receipt = workspace / "packet.mcp_evidence_receipt.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--packet-id",
                    "cli-pkt",
                    "--severity",
                    "High",
                    "--source-file",
                    "src.rs",
                    "--mcp-context-ref",
                    json.dumps(
                        {
                            "tool": "vault_hacker_brief_for_lane",
                            "context_pack_id": "auditooor.vault_hacker_brief_for_lane.v1:test",
                            "context_pack_hash": "a" * 64,
                        }
                    ),
                    "--out-json",
                    str(out_json),
                    "--out-mcp-evidence-receipt",
                    str(out_receipt),
                    "--strict",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            receipt = json.loads(out_receipt.read_text(encoding="utf-8"))

        self.assertEqual(receipt["schema"], "auditooor.mcp_evidence_receipt.v1")
        self.assertEqual(receipt["consumer_packet_hash"], payload["packet_hash"])
        self.assertEqual(receipt["callable"], "vault_hacker_brief_for_lane")


if __name__ == "__main__":
    unittest.main()
