from __future__ import annotations

import contextlib
import io
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "provider-keep-verification-backfill.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("provider_keep_verification_backfill_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, obj: object) -> None:
    _write(path, json.dumps(obj, indent=2) + "\n")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


class ProviderKeepVerificationBackfillTests(unittest.TestCase):
    def test_builds_packets_from_discipline_check_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            output = ws / "agent_outputs" / "provider_packets" / "slice" / "out.kimi.source.out.txt"
            _write(
                output,
                json.dumps(
                    {
                        "candidate_id": "CAND-001",
                        "verdict": "KEEP_FOR_LOCAL_VERIFICATION",
                        "reason": "source state looks plausible",
                    }
                ),
            )
            report = ws / "discipline.json"
            _write_json(
                report,
                {
                    "schema": "auditooor.provider_fanout_discipline_check.v1",
                    "sub_results": {
                        "keep_local_verification": {
                            "keep_missing_verification_examples": [
                                {
                                    "output_file": str(output),
                                    "dispatch_audit": str(ws / "dispatch_audit.jsonl"),
                                    "provider": "kimi",
                                    "task_type": "source-extract",
                                    "template_id": "source-extract",
                                }
                            ]
                        }
                    },
                },
            )

            payload = tool.build_backfill(workspace=ws, input_json=report, limit=10)

        self.assertEqual(payload["schema"], tool.SCHEMA)
        self.assertTrue(payload["offline_only"])
        self.assertFalse(payload["network_allowed"])
        self.assertFalse(payload["shell_executed"])
        self.assertEqual(payload["summary"]["packet_count"], 1)
        packet = payload["packets"][0]
        self.assertEqual(packet["source_file"], str(output))
        self.assertEqual(packet["provider"], "kimi")
        self.assertEqual(packet["task_type"], "source-extract")
        self.assertEqual(packet["missing_verification_reason"], "keep_without_local_verification_signal")
        self.assertEqual(
            {cmd["kind"] for cmd in packet["suggested_local_commands"]},
            {"rg", "source", "test"},
        )
        self.assertTrue(all(cmd["placeholder_only"] for cmd in packet["suggested_local_commands"]))
        self.assertTrue(all(cmd["executes"] is False for cmd in packet["suggested_local_commands"]))

    def test_workspace_scan_finds_keep_without_local_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            packet_dir = ws / "agent_outputs" / "provider_packets" / "slice"
            output = packet_dir / "out.minimax.kill.out.txt"
            _write(
                output,
                '{"candidate_id":"RISK-777","verdict":"KEEP_FOR_LOCAL_VERIFICATION","notes":"check `dangerousWithdraw`"}',
            )
            _write_jsonl(
                packet_dir / "dispatch_audit.jsonl",
                [
                    {
                        "ts": "2026-05-20T00:00:00Z",
                        "status": "DISPATCHED",
                        "provider": "minimax",
                        "model": "MiniMax-M2.7",
                        "task_type": "adversarial-kill",
                        "provider_output_path": str(output),
                    }
                ],
            )

            payload = tool.build_backfill(workspace=ws, scan_workspace=True, limit=10)

        self.assertEqual(payload["source_mode"], "workspace_scan")
        self.assertEqual(payload["summary"]["packet_count"], 1)
        packet = payload["packets"][0]
        self.assertEqual(packet["provider"], "minimax")
        self.assertEqual(packet["task_type"], "adversarial-kill")
        self.assertEqual(packet["missing_verification_reason"], "keep_without_local_verification_signal")
        rg_cmd = next(cmd["command"] for cmd in packet["suggested_local_commands"] if cmd["kind"] == "rg")
        self.assertIn("rg -n", rg_cmd)
        self.assertIn("dangerousWithdraw", rg_cmd)

    def test_workspace_scan_matches_discipline_keep_and_signal_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            packet_dir = ws / "agent_outputs" / "provider_packets" / "slice"
            advisory = packet_dir / "impact.txt"
            capitalized_fixture = packet_dir / "fixture.txt"
            _write(advisory, "MUST_KEEP_LOCAL_REVIEW: source state looks plausible")
            _write(capitalized_fixture, "KEEP_FOR_LOCAL_VERIFICATION\nFixture needed before promotion")
            _write_jsonl(
                packet_dir / "dispatch_audit.jsonl",
                [
                    {
                        "status": "DISPATCHED",
                        "provider": "minimax",
                        "task_type": "impact_analysis",
                        "provider_output_path": str(advisory),
                    },
                    {
                        "status": "DISPATCHED",
                        "provider": "minimax",
                        "task_type": "adversarial-kill",
                        "provider_output_path": str(capitalized_fixture),
                    },
                ],
            )

            payload = tool.build_backfill(workspace=ws, scan_workspace=True, limit=10)

        self.assertEqual(payload["summary"]["packet_count"], 2)
        self.assertEqual(
            {Path(packet["source_file"]).name for packet in payload["packets"]},
            {"impact.txt", "fixture.txt"},
        )

    def test_workspace_scan_skips_keep_with_existing_local_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            packet_dir = ws / "agent_outputs" / "provider_packets" / "slice"
            output = packet_dir / "out.kimi.source.out.txt"
            _write(
                output,
                '{"verdict":"KEEP_FOR_LOCAL_VERIFICATION","minimum_followup_check":"rg -n transfer tools"}',
            )
            _write_jsonl(
                packet_dir / "dispatch_audit.jsonl",
                [
                    {
                        "status": "DISPATCHED",
                        "provider": "kimi",
                        "task_type": "source-extract",
                        "provider_output_path": str(output),
                    }
                ],
            )

            payload = tool.build_backfill(workspace=ws, scan_workspace=True, limit=10)

        self.assertEqual(payload["summary"]["packet_count"], 0)
        self.assertEqual(payload["status"], "empty_no_keep_rows_missing_local_verification")

    def test_limit_and_dedupe_are_applied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            first = ws / "out1.txt"
            second = ws / "out2.txt"
            _write(first, '{"verdict":"KEEP_FOR_LOCAL_VERIFICATION"}')
            _write(second, '{"verdict":"KEEP_FOR_LOCAL_VERIFICATION"}')
            report = ws / "discipline.json"
            _write_json(
                report,
                {
                    "rows": [
                        {"output_file": str(first), "provider": "kimi", "task_type": "source-extract"},
                        {"output_file": str(first), "provider": "kimi", "task_type": "source-extract"},
                        {"output_file": str(second), "provider": "minimax", "task_type": "adversarial-kill"},
                    ]
                },
            )

            payload = tool.build_backfill(workspace=ws, input_json=report, limit=1)

        self.assertEqual(payload["summary"]["packet_count"], 1)
        self.assertEqual(payload["packets"][0]["source_file"], str(first))

    def test_discipline_gap_strings_are_parsed_when_example_list_is_capped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            files = [ws / f"out{i}.txt" for i in range(3)]
            for path in files:
                _write(path, "KEEP_FOR_LOCAL_VERIFICATION without local proof")
            report = ws / "discipline.json"
            _write_json(
                report,
                {
                    "schema": "auditooor.provider_fanout_discipline_check.v1",
                    "sub_results": {
                        "keep_local_verification": {
                            "keep_missing_verification_examples": [
                                {
                                    "output_file": str(files[0]),
                                    "provider": "kimi",
                                    "task_type": "source-extract",
                                }
                            ],
                            "gaps": [
                                f"gap:keep-missing-local-verification: {files[0]} "
                                "(task_type='source-extract', ts='2026-05-20T00:00:00Z') - KEEP verdict present",
                                f"gap:keep-missing-local-verification: {files[1]} "
                                "(task_type='impact_analysis', ts='2026-05-20T00:01:00Z') - KEEP verdict present",
                                f"gap:keep-missing-local-verification: {files[2]} "
                                "(task_type='adversarial-kill', ts='2026-05-20T00:02:00Z') - KEEP verdict present",
                            ],
                        }
                    },
                },
            )

            payload = tool.build_backfill(workspace=ws, input_json=report, limit=10)

        self.assertEqual(payload["summary"]["packet_count"], 3)
        self.assertEqual(
            {Path(packet["source_file"]).name for packet in payload["packets"]},
            {"out0.txt", "out1.txt", "out2.txt"},
        )

    def test_markdown_includes_required_classification_columns(self) -> None:
        payload = {
            "source_mode": "input_json",
            "summary": {"packet_count": 1},
            "shell_executed": False,
            "network_allowed": False,
            "packets": [
                {
                    "packet_id": "KEEP-BACKFILL-001",
                    "source_file": "out.txt",
                    "provider": "kimi",
                    "task_type": "source-extract",
                    "missing_verification_reason": "keep_without_local_verification_signal",
                    "suggested_local_commands": [{"kind": "rg", "command": "rg -n KEEP out.txt"}],
                }
            ],
        }

        markdown = tool.render_markdown(payload)

        self.assertIn("Source file", markdown)
        self.assertIn("Provider", markdown)
        self.assertIn("Task type", markdown)
        self.assertIn("Missing reason", markdown)
        self.assertIn("rg -n KEEP out.txt", markdown)

    def test_cli_writes_json_and_markdown_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            output = ws / "out.txt"
            report = ws / "discipline.json"
            out_json = ws / "backfill.json"
            out_md = ws / "backfill.md"
            _write(output, '{"verdict":"KEEP_FOR_LOCAL_VERIFICATION"}')
            _write_json(report, {"rows": [{"output_file": str(output), "provider": "kimi", "task_type": "source-extract"}]})

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = tool.main(
                    [
                        "--workspace",
                        str(ws),
                        "--input-json",
                        str(report),
                        "--out-json",
                        str(out_json),
                        "--out-md",
                        str(out_md),
                        "--json",
                    ]
                )

            parsed = json.loads(out_json.read_text(encoding="utf-8"))
            printed = json.loads(stdout.getvalue())
            markdown = out_md.read_text(encoding="utf-8")

        self.assertEqual(rc, 0)
        self.assertEqual(parsed["summary"]["packet_count"], 1)
        self.assertEqual(printed["summary"]["packet_count"], 1)
        self.assertIn("Provider KEEP Verification Backfill", markdown)


if __name__ == "__main__":
    unittest.main()
