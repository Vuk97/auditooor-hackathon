from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CAPACITY = ROOT / "tools" / "provider-capacity-report.py"
BATCH = ROOT / "tools" / "semantic-provider-batch.py"


def _import(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _seed_semantic_graph(ws: Path) -> None:
    graph = ws / ".auditooor" / "semantic_graph.json"
    graph.parent.mkdir(parents=True, exist_ok=True)
    graph.write_text(
        json.dumps({"schema": "auditooor.semantic_graph.v1", "relation_edges": [], "multi_hop_paths": []}),
        encoding="utf-8",
    )


def _write_worklist(ws: Path, tasks: list[dict[str, object]]) -> Path:
    worklist = ws / ".auditooor" / "semantic_detector_worklist.json"
    worklist.parent.mkdir(parents=True, exist_ok=True)
    worklist.write_text(
        json.dumps({"schema": "auditooor.semantic_detector_worklist.v1", "tasks": tasks}),
        encoding="utf-8",
    )
    return worklist


class ProviderCapacityReportTests(unittest.TestCase):
    def test_report_uses_active_paid_budget_for_planned_fanout(self) -> None:
        mod = _import(CAPACITY, "provider_capacity_report_test")
        budget = {
            "providers": {
                "kimi": {"max_calls": 180, "max_tokens": 1_800_000, "soft_ratio": 0.9},
                "minimax": {"max_calls": 240, "max_tokens": 2_400_000, "soft_ratio": 0.9},
            }
        }
        fanout = mod._fanout_from_budget(budget)
        self.assertEqual(fanout["budget_profile"], "paid-tier-aggressive-audited")
        self.assertGreaterEqual(fanout["kimi_source_extract"], 20)
        self.assertGreaterEqual(fanout["minimax_adversarial_kill"], 30)

    def test_report_records_next_command_when_live_probe_lacks_consent(self) -> None:
        mod = _import(CAPACITY, "provider_capacity_report_consent_test")
        mod._auth_rows = lambda: [
            {"provider": "kimi", "usable": True},
            {"provider": "minimax", "usable": True},
        ]
        mod._routing_rows = lambda: []
        mod._configured_defaults = lambda: {}
        mod._budget_log_summary = lambda: {"rows": 0, "by_provider": {}}
        mod._load_json = lambda _path: {"providers": {}}
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(
            "os.environ",
            {"AUDITOOOR_LLM_NETWORK_CONSENT": "", "ADVERSARIAL_LIVE_CONSENT": ""},
            clear=False,
        ):
            report = mod.build_report(out_dir=Path(td), live_probe=True, timeout=1)
        self.assertFalse(report["parallel_dispatch_safe"])
        self.assertEqual(report["recommended_per_loop_fanout"]["live_executable_kimi_source_extract"], 0)
        self.assertEqual(report["observed_live_smoke"][0]["status"], "blocked-no-network-consent")
        self.assertEqual(report["next_commands"][0]["reason"], "live_provider_dispatch_requires_operator_consent")
        self.assertIn("AUDITOOOR_LLM_NETWORK_CONSENT=1", report["next_commands"][0]["command"])
        self.assertIn("Next Commands", mod.render_md(report))

    def test_report_exposes_provider_models_and_recent_model_telemetry(self) -> None:
        mod = _import(CAPACITY, "provider_capacity_report_models_test")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "agent_outputs"
            audit_dir = root / "provider_packets" / "slice" / "dispatch_audit"
            audit_dir.mkdir(parents=True)
            (audit_dir / "llm_dispatch_1.json").write_text(
                json.dumps(
                    {
                        "provider": "minimax",
                        "model": "MiniMax-M2.7",
                        "outcome": "ok",
                        "task_type": "gate-hardening",
                        "response_length": 1234,
                        "timing_ms": 4567,
                        "timestamp": "2026-05-17T00:00:00+00:00",
                    }
                ),
                encoding="utf-8",
            )
            old_roots = mod.DISPATCH_AUDIT_ROOTS
            mod.DISPATCH_AUDIT_ROOTS = (root,)
            try:
                configured = {
                    "llm_dispatch": {
                        "default_models": {"kimi": "kimi-for-coding", "minimax": "MiniMax-M2.7"},
                        "default_base_url_hosts": {"kimi": "api.kimi.com", "minimax": "api.minimax.io"},
                    }
                }
                budget = {"providers": {"minimax": {"max_calls": 240, "max_tokens": 2_400_000, "soft_ratio": 0.9}}}
                registry = mod._model_registry(configured, budget)
                telemetry = mod._recent_dispatch_model_summary()
            finally:
                mod.DISPATCH_AUDIT_ROOTS = old_roots
        self.assertEqual(registry["minimax"]["active_model"], "MiniMax-M2.7")
        self.assertEqual(registry["minimax"]["model_env_var"], "MINIMAX_MODEL")
        self.assertIn("minimax:MiniMax-M2.7", telemetry["by_provider_model"])
        self.assertEqual(telemetry["by_provider_model"]["minimax:MiniMax-M2.7"]["calls"], 1)

    def test_report_workspace_readiness_names_missing_semantic_graph_command(self) -> None:
        mod = _import(CAPACITY, "provider_capacity_report_workspace_test")
        mod._auth_rows = lambda: []
        mod._routing_rows = lambda: []
        mod._configured_defaults = lambda: {}
        mod._budget_log_summary = lambda: {"rows": 0, "by_provider": {}}
        mod._load_json = lambda _path: {"providers": {}}
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            report = mod.build_report(out_dir=Path(td) / "out", live_probe=False, timeout=1, workspace=ws)
        readiness = report["workspace_readiness"]
        self.assertEqual(readiness["status"], "blocked_missing_semantic_graph")
        self.assertFalse(readiness["ready_for_semantic_provider_batch"])
        self.assertIn("make semantic-graph WS=", readiness["next_command"])
        self.assertIn("blocked_missing_semantic_graph", [row["reason"] for row in report["next_commands"]])


class SemanticProviderBatchTests(unittest.TestCase):
    def test_missing_semantic_graph_writes_readiness_next_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = base / "ws"
            ws.mkdir()
            out = base / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--out-dir",
                    str(out),
                    "--dry-run",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("next_command:", proc.stderr)
            self.assertIn("make semantic-graph WS=", proc.stderr)
            readiness = json.loads((out / "semantic_provider_batch_readiness.json").read_text(encoding="utf-8"))
            self.assertEqual(readiness["reason"], "missing_semantic_graph")
            self.assertEqual(readiness["status"], "blocked")
            self.assertIn("make semantic-graph WS=", readiness["next_command"])
            self.assertTrue(readiness["advisory_only"])
            md = (out / "semantic_provider_batch_readiness.md").read_text(encoding="utf-8")
            self.assertIn("## Next Command", md)
            self.assertIn("live providers still require explicit consent", md)

    def test_stale_worklist_without_semantic_graph_still_fails_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = base / "ws"
            ws.mkdir()
            worklist = _write_worklist(ws, [{"task_id": "SDW-STALE-001"}])
            out = base / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--out-dir",
                    str(out),
                    "--mock",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            readiness = json.loads((out / "semantic_provider_batch_readiness.json").read_text(encoding="utf-8"))
            self.assertEqual(readiness["reason"], "missing_semantic_graph")
            self.assertIn("build_semantic_graph", readiness["next_commands"])

    def test_live_batch_without_consent_writes_consent_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(
            "os.environ",
            {"AUDITOOOR_LLM_NETWORK_CONSENT": ""},
            clear=False,
        ):
            base = Path(td)
            ws = base / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Portal.sol").write_text("contract Portal { function f() external {} }\n", encoding="utf-8")
            _seed_semantic_graph(ws)
            worklist = _write_worklist(
                ws,
                [
                    {
                        "task_id": "SDW-CONSENT-001",
                        "candidate_detector_family": "verifier_relation",
                        "file": "src/Portal.sol",
                        "line": 1,
                    }
                ],
            )
            out = base / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--out-dir",
                    str(out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("safe_next_command:", proc.stderr)
            consent = json.loads((out / "semantic_provider_batch_consent.json").read_text(encoding="utf-8"))
            self.assertEqual(consent["reason"], "missing_live_provider_consent")
            self.assertIn("--dry-run", consent["safe_next_command"])
            self.assertIn("AUDITOOOR_LLM_NETWORK_CONSENT=1", consent["operator_live_command"])

    def test_mock_batch_writes_advisory_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = base / "ws"
            ws.mkdir()
            (ws / "src").mkdir()
            (ws / "src" / "Portal.sol").write_text(
                textwrap.dedent(
                    """
                    pragma solidity ^0.8.20;
                    contract Portal {
                        function finalize(bytes calldata proof) external {}
                    }
                    """
                ).strip() + "\n",
                encoding="utf-8",
            )
            worklist = ws / ".auditooor" / "semantic_detector_worklist.json"
            worklist.parent.mkdir()
            _seed_semantic_graph(ws)
            worklist.write_text(
                json.dumps(
                    {
                        "tasks": [
                            {
                                "task_id": "SDW-REL-001",
                                "candidate_detector_family": "verifier_relation",
                                "file": "src/Portal.sol",
                                "line": 3,
                                "source_id": "Portal.finalize",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = base / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--out-dir",
                    str(out),
                    "--limit",
                    "1",
                    "--mock",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "semantic_provider_batch.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["advisory_only"])
            self.assertFalse(manifest["promotion_authority"])
            self.assertEqual(manifest["summary"], {"ok": 1})
            self.assertEqual(manifest["provider_accounting"]["worklist_task_count"], 1)
            self.assertEqual(manifest["provider_accounting"]["selected_task_count"], 1)
            self.assertEqual(manifest["provider_accounting"]["loop_capacity"]["kimi_source_extract"], 22)
            self.assertEqual(manifest["provider_accounting"]["loop_capacity"]["minimax_adversarial_kill"], 30)
            self.assertEqual(manifest["provider_accounting"]["kimi_packets_queued"], 1)
            self.assertEqual(manifest["provider_accounting"]["minimax_packets_queued"], 1)
            self.assertEqual(manifest["provider_accounting"]["minimax_backlog_capacity_remaining"], 29)
            self.assertEqual(len(manifest["provider_packet_queue"]), 2)
            self.assertEqual(manifest["readiness"]["status"], "ready")
            self.assertIn("large_batch_mock", manifest["next_commands"])
            self.assertEqual(manifest["cursor"]["next_start_index"], 2)
            self.assertEqual(manifest["cursor"]["remaining_after_batch"], 0)
            self.assertIn("semantic-provider-batch.py --workspace", manifest["cursor"]["resume_command_hint"])
            state = json.loads((out / "semantic_provider_batch_state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["completed_task_ids"], ["SDW-REL-001"])
            md = (out / "semantic_provider_batch.md").read_text(encoding="utf-8")
            self.assertIn("22 Kimi source-extract packets + 30 Minimax adversarial-kill packets per loop", md)
            final = json.loads((out / "final" / "sdw-rel-001.provider-assist.json").read_text(encoding="utf-8"))
            self.assertEqual(final["severity"], "none")
            self.assertEqual(final["submission_posture"], "NOT_SUBMIT_READY")
            self.assertTrue(final["local_verification_required"])
            queue = json.loads((out / "provider_packet_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(len(queue), 2)
            self.assertIn("Provider Packet Queue", (out / "provider_packet_queue.md").read_text(encoding="utf-8"))
            kimi_prompt = (out / "prompts" / "sdw-rel-001.kimi.md").read_text(encoding="utf-8")
            self.assertIn("memory_context:", kimi_prompt)
            minimax_prompt = (out / "prompts" / "sdw-rel-001.minimax.md").read_text(encoding="utf-8")
            self.assertIn("memory_context:", minimax_prompt)

    def test_batch_cursor_resumes_from_real_worklist_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = base / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Portal.sol").write_text(
                "\n".join(
                    [
                        "pragma solidity ^0.8.20;",
                        "contract Portal {",
                        "  function finalize(bytes calldata proof) external {}",
                        "  function pause(address target) external {}",
                        "}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            worklist = ws / ".auditooor" / "semantic_detector_worklist.json"
            worklist.parent.mkdir()
            _seed_semantic_graph(ws)
            worklist.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_detector_worklist.v1",
                        "tasks": [
                            {
                                "task_id": "SDW-REL-001",
                                "candidate_detector_family": "verifier_relation",
                                "file": "src/Portal.sol",
                                "line": 3,
                                "source_id": "Portal.finalize",
                            },
                            {
                                "task_id": "SDW-REL-002",
                                "candidate_detector_family": "auth_relation",
                                "file": "src/Portal.sol",
                                "line": 4,
                                "source_id": "Portal.pause",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = base / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--out-dir",
                    str(out),
                    "--start-index",
                    "2",
                    "--limit",
                    "1",
                    "--mock",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "semantic_provider_batch.json").read_text(encoding="utf-8"))
            self.assertEqual([row["task_id"] for row in manifest["rows"]], ["SDW-REL-002"])
            self.assertEqual(manifest["cursor"]["start_index"], 2)
            self.assertEqual(manifest["cursor"]["next_start_index"], 3)
            self.assertEqual(manifest["cursor"]["remaining_after_batch"], 0)
            self.assertTrue(manifest["worklist_sha256"])

    def test_dispatch_concurrency_is_recorded_without_skipping_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = base / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Portal.sol").write_text(
                "\n".join(
                    ["pragma solidity ^0.8.20;", "contract Portal {"]
                    + [f"  function f{i}() external {{}}" for i in range(1, 7)]
                    + ["}"]
                )
                + "\n",
                encoding="utf-8",
            )
            _seed_semantic_graph(ws)
            worklist = _write_worklist(
                ws,
                [
                    {
                        "task_id": f"SDW-CONC-{i:03d}",
                        "candidate_detector_family": "verifier_relation",
                        "file": "src/Portal.sol",
                        "line": i + 1,
                        "source_id": f"Portal.f{i}",
                    }
                    for i in range(1, 7)
                ],
            )
            out = base / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--out-dir",
                    str(out),
                    "--limit",
                    "6",
                    "--dispatch-concurrency",
                    "4",
                    "--mock",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "semantic_provider_batch.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["provider_accounting"]["dispatch_concurrency"], 4)
            self.assertEqual(manifest["provider_accounting"]["selected_task_count"], 6)
            self.assertEqual(manifest["summary"], {"ok": 6})
            self.assertEqual([row["task_id"] for row in manifest["rows"]], [f"SDW-CONC-{i:03d}" for i in range(1, 7)])
            self.assertEqual(manifest["cursor"]["next_start_index"], 7)
            md = (out / "semantic_provider_batch.md").read_text(encoding="utf-8")
            self.assertIn("dispatch concurrency: `4`", md)

    def test_explicit_limit_does_not_advance_past_unqueued_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = base / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Portal.sol").write_text(
                "\n".join(
                    ["pragma solidity ^0.8.20;", "contract Portal {"]
                    + [f"  function f{i}() external {{}}" for i in range(1, 18)]
                    + ["}"]
                )
                + "\n",
                encoding="utf-8",
            )
            _seed_semantic_graph(ws)
            worklist = _write_worklist(
                ws,
                [
                    {
                        "task_id": f"SDW-REL-{i:03d}",
                        "candidate_detector_family": "verifier_relation",
                        "file": "src/Portal.sol",
                        "line": i + 1,
                        "source_id": f"Portal.f{i}",
                    }
                    for i in range(1, 17)
                ],
            )
            out = base / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--out-dir",
                    str(out),
                    "--start-index",
                    "1",
                    "--limit",
                    "16",
                    "--kimi-limit",
                    "8",
                    "--minimax-limit",
                    "8",
                    "--mock",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "semantic_provider_batch.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["provider_accounting"]["selected_task_count"], 8)
            self.assertEqual(manifest["provider_accounting"]["current_loop_paired_rows"], 8)
            self.assertEqual(manifest["summary"], {"ok": 8})
            self.assertEqual(manifest["cursor"]["next_start_index"], 9)
            self.assertEqual(manifest["cursor"]["remaining_after_batch"], 8)
            self.assertIn("--start-index 9", manifest["cursor"]["resume_command_hint"])

    def test_default_loop_models_22_kimi_and_30_minimax_slots(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = base / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Portal.sol").write_text(
                "\n".join(
                    ["pragma solidity ^0.8.20;", "contract Portal {"]
                    + [f"  function f{i}() external {{}}" for i in range(1, 36)]
                    + ["}"]
                )
                + "\n",
                encoding="utf-8",
            )
            tasks = [
                {
                    "task_id": f"SDW-REL-{i:03d}",
                    "candidate_detector_family": "verifier_relation",
                    "file": "src/Portal.sol",
                    "line": i + 1,
                    "source_id": f"Portal.f{i}",
                }
                for i in range(1, 36)
            ]
            worklist = ws / ".auditooor" / "semantic_detector_worklist.json"
            worklist.parent.mkdir()
            _seed_semantic_graph(ws)
            worklist.write_text(
                json.dumps({"schema": "auditooor.semantic_detector_worklist.v1", "tasks": tasks}),
                encoding="utf-8",
            )
            out = base / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--out-dir",
                    str(out),
                    "--mock",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "semantic_provider_batch.json").read_text(encoding="utf-8"))
            accounting = manifest["provider_accounting"]
            self.assertEqual(accounting["selected_task_count"], 30)
            self.assertEqual(accounting["kimi_packets_queued"], 22)
            self.assertEqual(accounting["minimax_packets_queued"], 30)
            self.assertEqual(accounting["current_loop_paired_rows"], 22)
            self.assertEqual(accounting["minimax_backlog_or_placeholder_rows"], 8)
            self.assertEqual(accounting["kimi_capacity_remaining"], 0)
            self.assertEqual(accounting["minimax_capacity_remaining"], 0)
            self.assertEqual(manifest["cursor"]["next_start_index"], 31)
            self.assertEqual(manifest["cursor"]["remaining_after_batch"], 5)
            self.assertIn("--kimi-limit 22 --minimax-limit 30", manifest["cursor"]["resume_command_hint"])
            minimax_placeholders = [
                row for row in manifest["provider_packet_queue"]
                if row.get("slot_class") == "minimax_backlog_or_placeholder"
            ]
            self.assertEqual(len(minimax_placeholders), 8)
            self.assertEqual(minimax_placeholders[0]["depends_on"], "prior-or-future-kimi-output-required")
            md = (out / "semantic_provider_batch.md").read_text(encoding="utf-8")
            self.assertIn("Minimax backlog/placeholder rows: `8`", md)
            resume = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--out-dir",
                    str(out),
                    "--start-index",
                    "31",
                    "--mock",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(resume.returncode, 0, resume.stderr)
            state = json.loads((out / "semantic_provider_batch_state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["previous_completed_task_count"], 30)
            self.assertEqual(state["cumulative_completed_task_count"], 35)
            self.assertEqual(len(state["completed_task_ids"]), 35)
            self.assertEqual(state["batch_completed_task_ids"], [f"SDW-REL-{i:03d}" for i in range(31, 36)])

    def test_large_batch_mock_queues_50_paired_rows_and_records_resume(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = base / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Portal.sol").write_text(
                "\n".join(["pragma solidity ^0.8.20;", "contract Portal {"]
                          + [f"  function f{i}() external {{}}" for i in range(1, 61)]
                          + ["}"]) + "\n",
                encoding="utf-8",
            )
            _seed_semantic_graph(ws)
            worklist = _write_worklist(
                ws,
                [
                    {
                        "task_id": f"SDW-LARGE-{i:03d}",
                        "candidate_detector_family": "verifier_relation",
                        "file": "src/Portal.sol",
                        "line": i + 1,
                        "source_id": f"Portal.f{i}",
                    }
                    for i in range(1, 61)
                ],
            )
            out = base / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(BATCH),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--out-dir",
                    str(out),
                    "--large-batch",
                    "--mock",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "semantic_provider_batch.json").read_text(encoding="utf-8"))
            accounting = manifest["provider_accounting"]
            self.assertTrue(accounting["large_batch"])
            self.assertEqual(accounting["selected_task_count"], 50)
            self.assertEqual(accounting["kimi_packets_queued"], 50)
            self.assertEqual(accounting["minimax_packets_queued"], 50)
            self.assertEqual(accounting["current_loop_paired_rows"], 50)
            self.assertEqual(manifest["cursor"]["next_start_index"], 51)
            self.assertEqual(manifest["cursor"]["remaining_after_batch"], 10)
            self.assertIn("--start-index 51", manifest["next_commands"]["resume"])
            state = json.loads((out / "semantic_provider_batch_state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["last_run_status"], "ok")
            self.assertEqual(state["cumulative_completed_task_count"], 50)
            queue = json.loads((out / "provider_packet_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(len(queue), 100)


if __name__ == "__main__":
    unittest.main()
