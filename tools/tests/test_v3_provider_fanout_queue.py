#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "v3-provider-fanout-queue.py"
PREFLIGHT = ROOT / "tools" / "dispatch-preflight.py"
RUNNER = ROOT / "tools" / "v3-provider-fanout-runner.py"
CLOSEOUT = ROOT / "tools" / "v3-provider-fanout-closeout.py"
MAKEFILE = ROOT / "Makefile"


def _load_tool():
    spec = importlib.util.spec_from_file_location("v3_provider_fanout_queue", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_followup_result(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "campaign_id": "unit-source",
                "run_id": "unit-run",
                "summary": {
                    "rows": 3,
                    "by_status": {"needs_more_source": 1, "pending": 1, "verified": 1},
                    "by_terminal_outcome": {"needs_more_source": 1},
                },
                "rows": [
                    {
                        "queue_id": "V3-LV-001",
                        "provider": "kimi",
                        "model": "kimi-for-coding",
                        "route": "external_source_needed",
                        "verification_status": "needs_more_source",
                        "terminal_outcome": "needs_more_source",
                        "terminal_safe": True,
                        "claim": {"kind": "proof_obligation", "summary": "Need primary source URL"},
                        "existing_source_ref_count": 0,
                        "missing_source_ref_count": 1,
                        "grep_hit_count": 0,
                        "verification": {"evidence_refs": []},
                    },
                    {
                        "queue_id": "V3-LV-002",
                        "provider": "kimi",
                        "model": "kimi-for-coding",
                        "route": "fixture_needed",
                        "verification_status": "verified",
                        "terminal_outcome": None,
                        "terminal_safe": False,
                        "claim": {"kind": "proof_obligation", "summary": "Needs clean control"},
                        "existing_source_ref_count": 1,
                        "missing_source_ref_count": 0,
                        "grep_hit_count": 1,
                        "verification": {
                            "evidence_refs": [
                                {"kind": "local_file", "path": "tools/example.py", "verified": True}
                            ]
                        },
                    },
                    {
                        "queue_id": "V3-LV-003",
                        "provider": "minimax",
                        "model": "MiniMax-M2.7",
                        "route": "kill_review",
                        "verification_status": "pending",
                        "terminal_outcome": None,
                        "terminal_safe": False,
                        "claim": {"kind": "kill_reason", "summary": "Needs exact contradiction"},
                        "existing_source_ref_count": 0,
                        "missing_source_ref_count": 0,
                        "grep_hit_count": 0,
                        "verification": {"evidence_refs": []},
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _write_prefiling_result(path: Path) -> None:
    results = [
        {
            "candidate_id": "EQ-002",
            "title": "Admin-controlled config drains rewards",
            "verdict": "fail",
            "claimed_severity": "High",
            "blocked_reasons": ["missing_or_vague_permissionless_action"],
            "warnings": [],
            "next_action": "Write the exact unprivileged attacker transaction before dispatching PoC work.",
            "questions": {
                "permissionless_action": {
                    "answer": "Admin sets unsafe config.",
                    "status": "fail",
                },
                "rubric_row": {"answer": "Direct theft of any user funds", "status": "pass"},
                "prior_disclosure": {"status": "clean", "gate_status": "pass", "citations": ["prior.md:10"]},
                "economics": {"status": "pass", "missing_fields": []},
                "production_harness": {"status": "pass", "blockers": []},
            },
        },
        {
            "candidate_id": "EQ-003",
            "title": "Generic critical impact without rubric row",
            "verdict": "fail",
            "claimed_severity": "Critical",
            "blocked_reasons": ["missing_exact_rubric_row", "rubric_row_not_found_in_severity_file"],
            "warnings": [],
            "next_action": "Map the candidate to a verbatim in-scope rubric row before PoC work.",
            "questions": {
                "permissionless_action": {"answer": "Any user calls withdraw().", "status": "pass"},
                "rubric_row": {
                    "answer": "Generic critical impact",
                    "status": "fail",
                    "found_in_workspace_severity_file": False,
                },
                "prior_disclosure": {"status": "clean", "gate_status": "pass", "citations": ["prior.md:20"]},
                "economics": {"status": "pass", "missing_fields": []},
                "production_harness": {"status": "pass", "blockers": []},
            },
        },
        {
            "candidate_id": "EQ-008",
            "title": "Possible duplicate withdrawal rounding path",
            "verdict": "fail",
            "claimed_severity": "High",
            "blocked_reasons": ["prior_disclosure_possible_dupe"],
            "warnings": [],
            "next_action": "Run prior disclosure/originality check and write a Q1/Q2 rebuttal before PoC work.",
            "questions": {
                "permissionless_action": {"answer": "Any user calls redeem().", "status": "pass"},
                "rubric_row": {"answer": "Theft of unclaimed yield", "status": "pass"},
                "prior_disclosure": {
                    "status": "possible_dupe",
                    "gate_status": "fail",
                    "citations": ["prior_audits/rounding.md:4"],
                },
                "economics": {"status": "pass", "missing_fields": []},
                "production_harness": {"status": "pass", "blockers": []},
            },
        },
        {
            "candidate_id": "EQ-009",
            "title": "Reward extraction lacks profit proof",
            "verdict": "warn",
            "claimed_severity": "High",
            "blocked_reasons": [],
            "warnings": ["missing_economics_proof_for_value_claim"],
            "next_action": "Resolve warnings before spending High/Critical PoC effort.",
            "questions": {
                "permissionless_action": {"answer": "Any user places reward order.", "status": "pass"},
                "rubric_row": {"answer": "Theft of unclaimed yield", "status": "pass"},
                "prior_disclosure": {"status": "clean", "gate_status": "pass", "citations": ["prior.md:30"]},
                "economics": {
                    "status": "warn",
                    "missing_fields": ["capital_lock_or_cost", "profit_or_loss_statement"],
                },
                "production_harness": {"status": "pass", "blockers": []},
            },
        },
        {
            "candidate_id": "EQ-010",
            "title": "Cosmos runtime claim without production harness",
            "verdict": "fail",
            "claimed_severity": "High",
            "blocked_reasons": [
                "cosmos_harness_preflight_blocked",
                "production_harness_execution_not_attempted",
                "harness_domain_mismatch",
            ],
            "warnings": [],
            "next_action": "Change the planned PoC shape to satisfy the required evidence class before coding.",
            "questions": {
                "permissionless_action": {"answer": "Any user submits MsgWithdraw.", "status": "pass"},
                "rubric_row": {"answer": "Permanent freezing of funds", "status": "pass"},
                "prior_disclosure": {"status": "clean", "gate_status": "pass", "citations": ["prior.md:40"]},
                "economics": {"status": "pass", "missing_fields": []},
                "production_harness": {
                    "status": "fail",
                    "blockers": [
                        "cosmos_harness_preflight_blocked",
                        "production_harness_execution_not_attempted",
                        "harness_domain_mismatch",
                    ],
                },
            },
        },
    ]
    path.write_text(
        json.dumps(
            {
                "schema_version": "auditooor.prefiling_stress_test.v1",
                "generated_at_utc": "2026-05-20T00:00:00Z",
                "source_type": "exploit_queue",
                "rows_assessed": len(results),
                "summary": {"fail": 4, "warn": 1, "pass": 0},
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_prefiling_all_pass_result(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "auditooor.prefiling_stress_test.v1",
                "generated_at_utc": "2026-05-20T00:00:00Z",
                "source_type": "exploit_queue",
                "rows_assessed": 1,
                "summary": {"pass": 1},
                "results": [
                    {
                        "candidate_id": "EQ-PASS",
                        "title": "Clean candidate",
                        "verdict": "pass",
                        "questions": {
                            "permissionless_action": {"status": "pass"},
                            "rubric_row": {"status": "pass"},
                            "prior_disclosure": {"status": "clean", "gate_status": "pass"},
                            "economics": {"status": "pass"},
                            "production_harness": {"status": "pass"},
                        },
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


class V3ProviderFanoutQueueTest(unittest.TestCase):
    def test_cli_writes_8_kimi_8_minimax_queue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "queue"
            workspace.mkdir()
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                    "--campaign-id",
                    "unit-test-v3",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["provider_counts"], {"kimi": 8, "minimax": 8})
            manifest = json.loads((out / "v3_provider_fanout_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["total_tasks"], 16)
            self.assertEqual(manifest["provider_counts"], {"kimi": 8, "minimax": 8})
            self.assertTrue((out / "v3_provider_fanout_queue.jsonl").is_file())
            self.assertIn(
                "dispatch-preflight.py --require-mcp-context",
                manifest["mcp_context_gate"],
            )
            for row in manifest["rows"]:
                self.assertTrue(row["requires_dispatch_preflight"])
                self.assertTrue(row["requires_mcp_context"])
                self.assertTrue(row["advisory_only"])
                self.assertTrue(row["local_verification_required"])
                self.assertIn("--require-mcp-context", row["dispatch_command"])
                self.assertEqual(row["dispatch_command"][0:2], ["python3", "tools/dispatch-preflight.py"])
                prompt = Path(row["prompt_path"])
                self.assertTrue(prompt.is_file())
                text = prompt.read_text(encoding="utf-8")
                self.assertIn("workspace_path:", text)
                self.assertIn("memory_context:", text)
                self.assertIn("expected_output_shape:", text)
                if row["provider"] == "kimi":
                    self.assertIn("source_packet:", text)
                    self.assertIn("Provider cannot read local filesystem paths", text)
                command = row["dispatch_command"]
                self.assertIn("--operator-live-network-consent", command[-1])
                self.assertIn("--require-mcp-receipt", command[-1])
                self.assertIn("--strategic-llm-allowed", command[-1])
                self.assertIn("--timeout", command[-1])
                self.assertIn("--audit-dir", command[-1])

    def test_cli_writes_followup_queue_from_local_verification_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "followup"
            workspace.mkdir()
            result = Path(tmp) / "result.json"
            _write_followup_result(result)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                    "--campaign-id",
                    "unit-followup",
                    "--mode",
                    "followup",
                    "--followup-source-result",
                    str(result),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["provider_counts"], {"kimi": 8, "minimax": 8})
            manifest = json.loads((out / "v3_provider_fanout_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["mode"], "followup")
            self.assertEqual(manifest["source_result"], str(result.resolve()))
            self.assertEqual(manifest["source_result_summary"]["rows"], 3)
            self.assertEqual(manifest["total_tasks"], 16)
            for row in manifest["rows"]:
                self.assertIn("--require-mcp-context", row["dispatch_command"])
                prompt = Path(row["prompt_path"]).read_text(encoding="utf-8")
                self.assertIn("memory_context:", prompt)
                self.assertIn("expected_output_shape:", prompt)
                self.assertIn("Provider output is advisory only", prompt)
                if row["provider"] == "kimi":
                    self.assertIn("target_files:", prompt)
                    self.assertIn("local_verification_rows:", prompt)
                else:
                    self.assertIn("candidate_list:", prompt)
                    self.assertIn("oos_text:", prompt)

    def test_followup_prompts_pass_template_preflight_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "followup"
            receipt_dir = workspace / ".auditooor"
            receipt_dir.mkdir(parents=True)
            (receipt_dir / "last_mcp_recall.json").write_text(
                json.dumps(
                    {
                        "recall_ts": time.time(),
                        "context_pack_id": "auditooor.vault_context_pack.v1:test",
                        "context_pack_hash": "test",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = Path(tmp) / "result.json"
            _write_followup_result(result)
            build = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                    "--mode",
                    "followup",
                    "--followup-source-result",
                    str(result),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            manifest = json.loads((out / "v3_provider_fanout_queue.json").read_text(encoding="utf-8"))
            for row in manifest["rows"]:
                preflight = subprocess.run(
                    [
                        sys.executable,
                        str(PREFLIGHT),
                        "--template",
                        row["template"],
                        "--task-type",
                        row["task_type"],
                        "--prompt-file",
                        row["prompt_path"],
                        "--workspace",
                        str(workspace),
                        "--provider",
                        row["provider"],
                        "--require-mcp-context",
                        "--dry-run",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(preflight.returncode, 0, preflight.stderr)

    def test_prefiling_backfill_queue_writes_8_kimi_8_minimax_and_passes_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "prefiling"
            receipt_dir = workspace / ".auditooor"
            source_artifacts = Path(tmp) / "source_artifacts"
            receipt_dir.mkdir(parents=True)
            source_artifacts.mkdir()
            (receipt_dir / "last_mcp_recall.json").write_text(
                json.dumps(
                    {
                        "recall_ts": time.time(),
                        "context_pack_id": "auditooor.vault_context_pack.v1:test",
                        "context_pack_hash": "test",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (source_artifacts / "refs.md").write_text(
                "# Source refs\n\n- EQ-002: contracts/Vault.sol:10\n",
                encoding="utf-8",
            )
            result = Path(tmp) / "prefiling_stress_test.json"
            _write_prefiling_result(result)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                    "--campaign-id",
                    "unit-prefiling",
                    "--mode",
                    "prefiling-backfill",
                    "--prefiling-source-result",
                    str(result),
                    "--prefiling-source-artifact-dir",
                    str(source_artifacts),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["provider_counts"], {"kimi": 8, "minimax": 8})
            manifest = json.loads((out / "v3_provider_fanout_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["mode"], "prefiling-backfill")
            self.assertEqual(manifest["total_tasks"], 16)
            self.assertEqual(manifest["provider_counts"], {"kimi": 8, "minimax": 8})
            self.assertEqual(manifest["source_result"], str(result.resolve()))
            self.assertEqual(manifest["source_artifact_dir"], str(source_artifacts.resolve()))
            self.assertTrue(manifest["advisory_only"])
            self.assertTrue(manifest["local_verification_required"])
            self.assertEqual(manifest["source_result_summary"]["targeted_rows"], 5)
            self.assertEqual(manifest["source_result_summary"]["summary"], {"fail": 4, "pass": 0, "warn": 1})
            self.assertEqual([row["provider"] for row in manifest["rows"]].count("kimi"), 8)
            self.assertEqual([row["provider"] for row in manifest["rows"]].count("minimax"), 8)

            for row in manifest["rows"]:
                self.assertTrue(row["advisory_only"])
                self.assertTrue(row["local_verification_required"])
                self.assertEqual(row["template_label"], row["template"])
                prompt = Path(row["prompt_path"]).read_text(encoding="utf-8")
                self.assertIn(f"template_label: {row['template']}", prompt)
                self.assertIn("mode: prefiling-backfill", prompt)
                self.assertIn("local_verification_required: true", prompt)
                if row["provider"] == "kimi":
                    self.assertEqual(row["template"], "source-extract")
                    self.assertIn("exact attacker actions/source refs", prompt)
                    self.assertIn("- EQ-002: contracts/Vault.sol:10", prompt)
                    self.assertIn("prefiling_rows:", prompt)
                else:
                    self.assertEqual(row["template"], "adversarial-kill")
                    self.assertIn("REJECT_OOS", prompt)
                    self.assertIn("REJECT_DUPLICATE", prompt)
                    self.assertIn("REJECT_ECONOMICS_WEAK", prompt)
                    self.assertIn("REJECT_ADMIN_DEPENDENT", prompt)
                    self.assertIn("REJECT_ONE_FIX", prompt)

                preflight = subprocess.run(
                    [
                        sys.executable,
                        str(PREFLIGHT),
                        "--template",
                        row["template"],
                        "--task-type",
                        row["task_type"],
                        "--prompt-file",
                        row["prompt_path"],
                        "--workspace",
                        str(workspace),
                        "--provider",
                        row["provider"],
                        "--require-mcp-context",
                        "--dry-run",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(preflight.returncode, 0, preflight.stderr)

    def test_prefiling_backfill_gate_status_fail_is_not_masked_by_clean_status(self) -> None:
        module = _load_tool()
        row = {
            "candidate_id": "EQ-GATE",
            "verdict": "pass",
            "questions": {
                "prior_disclosure": {
                    "status": "clean",
                    "gate_status": "fail",
                    "citations": ["prior.md:1"],
                }
            },
        }
        self.assertIn("prior_disclosure", module._prefiling_row_blockers(row))
        self.assertEqual(module._prefiling_target_rows([row]), [row])

    def test_prefiling_backfill_missing_result_fails_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--mode",
                    "prefiling-backfill",
                    "--prefiling-source-result",
                    str(Path(tmp) / "missing.json"),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("cannot read JSON input", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)

    def test_prefiling_backfill_refuses_empty_all_pass_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "prefiling"
            workspace.mkdir()
            result = Path(tmp) / "all_pass.json"
            _write_prefiling_all_pass_result(result)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                    "--mode",
                    "prefiling-backfill",
                    "--prefiling-source-result",
                    str(result),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("no fail/warn/blocker rows", proc.stderr)
            self.assertFalse((out / "v3_provider_fanout_queue.json").exists())

    def test_followup_mode_requires_source_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--mode",
                    "followup",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("requires --followup-source-result", proc.stderr)

    def test_generated_prompts_pass_template_and_mcp_preflight_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "queue"
            receipt_dir = workspace / ".auditooor"
            receipt_dir.mkdir(parents=True)
            (receipt_dir / "last_mcp_recall.json").write_text(
                json.dumps(
                    {
                        "recall_ts": time.time(),
                        "context_pack_id": "auditooor.vault_context_pack.v1:test",
                        "context_pack_hash": "test",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            workspace.mkdir(exist_ok=True)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "v3_provider_fanout_queue.json").read_text(encoding="utf-8"))
            for row in manifest["rows"]:
                cmd = [
                    sys.executable,
                    str(PREFLIGHT),
                    "--template",
                    row["template"],
                    "--task-type",
                    row["task_type"],
                    "--prompt-file",
                    row["prompt_path"],
                    "--workspace",
                    str(workspace),
                    "--provider",
                    row["provider"],
                    "--require-mcp-context",
                    "--dry-run",
                ]
                preflight = subprocess.run(
                    cmd,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(preflight.returncode, 0, preflight.stderr)

    def test_manifest_is_built_from_declared_static_tasks(self) -> None:
        module = _load_tool()
        self.assertEqual(len(module.KIMI_TASKS), 8)
        self.assertEqual(len(module.MINIMAX_TASKS), 8)
        self.assertTrue(all(task.template == "source-extract" for task in module.KIMI_TASKS))
        self.assertTrue(all(task.template == "adversarial-kill" for task in module.MINIMAX_TASKS))

    def test_runner_uses_preflight_and_materializes_minimax_from_kimi_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "queue"
            workspace.mkdir()
            receipt_dir = workspace / ".auditooor"
            receipt_dir.mkdir(parents=True)
            (receipt_dir / "last_mcp_recall.json").write_text(
                json.dumps(
                    {
                        "recall_ts": time.time(),
                        "context_pack_id": "auditooor.vault_context_pack.v1:test",
                        "context_pack_hash": "test",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            mock = Path(tmp) / "mock_dispatcher.py"
            mock.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "print('MOCK-DISPATCH-OK')\n"
                "print(json.dumps({'argv': sys.argv[1:]}))\n",
                encoding="utf-8",
            )
            os.chmod(mock, 0o755)
            build = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            run_dir = Path(tmp) / "run"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--workspace",
                    str(workspace),
                    "--queue",
                    str(out / "v3_provider_fanout_queue.json"),
                    "--out-dir",
                    str(run_dir),
                    "--mock-dispatcher",
                    str(mock),
                    "--operator-live-network-consent",
                    "--parallel",
                    "16",
                    "--kimi-parallel",
                    "8",
                    "--minimax-parallel",
                    "8",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["summary"], {"ok": 16})
            manifest = json.loads((run_dir / "v3_provider_fanout_run.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["summary"], {"ok": 16})
            minimax_prompt = run_dir / "minimax_prompts" / "minimax-01-external-intel-kill.md"
            self.assertTrue(minimax_prompt.is_file())
            minimax_text = minimax_prompt.read_text(encoding="utf-8")
            self.assertIn("## Kimi Outputs To Review", minimax_text)
            self.assertIn("MOCK-DISPATCH-OK", minimax_text)
            self.assertTrue(all(row["env_summary"]["AUDITOOOR_CAMPAIGN_ID"] == "hackerman-v3-8kimi-8minimax" for row in manifest["rows"]))
            self.assertTrue(all(row["env_summary"]["AUDITOOOR_LLM_NETWORK_CONSENT"] == "1" for row in manifest["rows"]))

    def test_runner_minimax_only_defaults_to_block_without_kimi_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "queue"
            workspace.mkdir()
            receipt_dir = workspace / ".auditooor"
            receipt_dir.mkdir(parents=True)
            (receipt_dir / "last_mcp_recall.json").write_text(
                json.dumps(
                    {
                        "recall_ts": time.time(),
                        "context_pack_id": "auditooor.vault_context_pack.v1:test",
                        "context_pack_hash": "test",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            build = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            mock = Path(tmp) / "mock_dispatcher.py"
            mock.write_text("#!/usr/bin/env python3\nprint('SHOULD-NOT-RUN')\n", encoding="utf-8")
            os.chmod(mock, 0o755)
            run_dir = Path(tmp) / "run"
            run = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--workspace",
                    str(workspace),
                    "--queue",
                    str(out / "v3_provider_fanout_queue.json"),
                    "--out-dir",
                    str(run_dir),
                    "--provider",
                    "minimax",
                    "--mock-dispatcher",
                    str(mock),
                    "--operator-live-network-consent",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            summary = json.loads(run.stdout)
            self.assertEqual(summary["summary"], {"blocked_kimi_outputs_missing": 8})
            manifest = json.loads((run_dir / "v3_provider_fanout_run.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["minimax_standalone_advisory"])
            self.assertTrue(all(row["status"] == "blocked_kimi_outputs_missing" for row in manifest["rows"]))
            self.assertTrue(all(row["kimi_unavailable"] for row in manifest["rows"]))
            self.assertTrue(all(row["local_verification_required"] for row in manifest["rows"]))
            self.assertTrue(all(row["standalone_advisory"] is False for row in manifest["rows"]))
            self.assertEqual(list((run_dir / "provider_outputs").glob("*.out.txt")), [])

    def test_runner_minimax_standalone_advisory_records_kimi_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "queue"
            workspace.mkdir()
            receipt_dir = workspace / ".auditooor"
            receipt_dir.mkdir(parents=True)
            (receipt_dir / "last_mcp_recall.json").write_text(
                json.dumps(
                    {
                        "recall_ts": time.time(),
                        "context_pack_id": "auditooor.vault_context_pack.v1:test",
                        "context_pack_hash": "test",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            build = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            mock = Path(tmp) / "mock_dispatcher.py"
            mock.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "print('MINIMAX-STANDALONE-OK')\n"
                "print(json.dumps({'argv': sys.argv[1:]}))\n",
                encoding="utf-8",
            )
            os.chmod(mock, 0o755)
            run_dir = Path(tmp) / "run"
            run = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--workspace",
                    str(workspace),
                    "--queue",
                    str(out / "v3_provider_fanout_queue.json"),
                    "--out-dir",
                    str(run_dir),
                    "--provider",
                    "minimax",
                    "--minimax-standalone-advisory",
                    "--mock-dispatcher",
                    str(mock),
                    "--operator-live-network-consent",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            summary = json.loads(run.stdout)
            self.assertEqual(summary["summary"], {"ok": 8})
            manifest = json.loads((run_dir / "v3_provider_fanout_run.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["minimax_standalone_advisory"])
            self.assertEqual(manifest["minimax_standalone_advisory_scope"], "provider=minimax")
            self.assertTrue(manifest["kimi_unavailable"])
            self.assertTrue(manifest["local_verification_required"])
            self.assertTrue(all(row["provider"] == "minimax" for row in manifest["rows"]))
            self.assertTrue(all(row["standalone_advisory"] for row in manifest["rows"]))
            self.assertTrue(all(row["kimi_unavailable"] for row in manifest["rows"]))
            self.assertTrue(all(row["local_verification_required"] for row in manifest["rows"]))
            prompt_path = Path(manifest["rows"][0]["prompt_path"])
            prompt_text = prompt_path.read_text(encoding="utf-8")
            self.assertIn("## MiniMax Standalone Advisory Mode", prompt_text)
            self.assertIn("- kimi_unavailable: true", prompt_text)
            self.assertIn("- local_verification_required: true", prompt_text)
            self.assertIn("NO_SUCCESSFUL_KIMI_OUTPUT", prompt_text)
            self.assertIn("independent review input", prompt_text)

    def test_runner_minimax_standalone_advisory_requires_minimax_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "queue"
            workspace.mkdir()
            build = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--workspace",
                    str(workspace),
                    "--queue",
                    str(out / "v3_provider_fanout_queue.json"),
                    "--out-dir",
                    str(Path(tmp) / "run"),
                    "--provider",
                    "kimi",
                    "--minimax-standalone-advisory",
                    "--dry-run",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("--minimax-standalone-advisory requires --provider minimax", run.stderr)
            self.assertNotIn("Traceback", run.stderr)

    def test_followup_runner_and_closeout_preserve_campaign_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "followup"
            workspace.mkdir()
            receipt_dir = workspace / ".auditooor"
            receipt_dir.mkdir(parents=True)
            (receipt_dir / "last_mcp_recall.json").write_text(
                json.dumps(
                    {
                        "recall_ts": time.time(),
                        "context_pack_id": "auditooor.vault_context_pack.v1:test",
                        "context_pack_hash": "test",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = Path(tmp) / "result.json"
            _write_followup_result(result)
            build = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                    "--campaign-id",
                    "unit-followup",
                    "--mode",
                    "followup",
                    "--followup-source-result",
                    str(result),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            mock = Path(tmp) / "mock_dispatcher.py"
            mock.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "print(json.dumps({'ok': True, 'argv': sys.argv[1:]}))\n",
                encoding="utf-8",
            )
            os.chmod(mock, 0o755)
            run_dir = Path(tmp) / "run"
            run = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--workspace",
                    str(workspace),
                    "--queue",
                    str(out / "v3_provider_fanout_queue.json"),
                    "--out-dir",
                    str(run_dir),
                    "--mock-dispatcher",
                    str(mock),
                    "--operator-live-network-consent",
                    "--parallel",
                    "16",
                    "--kimi-parallel",
                    "8",
                    "--minimax-parallel",
                    "8",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            run_manifest = json.loads((run_dir / "v3_provider_fanout_run.json").read_text(encoding="utf-8"))
            self.assertEqual(run_manifest["campaign_id"], "unit-followup")

            closeout = subprocess.run(
                [
                    sys.executable,
                    str(CLOSEOUT),
                    "--workspace",
                    str(workspace),
                    "--run",
                    str(run_dir / "v3_provider_fanout_run.json"),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(closeout.stderr, "")
            self.assertEqual(closeout.returncode, 1, "mock dispatch lacks model audit metadata by design")
            closeout_payload = json.loads((run_dir / "fanout_closeout.json").read_text(encoding="utf-8"))
            self.assertEqual(closeout_payload["campaign_id"], "unit-followup")

    def test_runner_fails_closed_without_mcp_receipt_even_in_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            out = Path(tmp) / "queue"
            workspace.mkdir()
            build = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(workspace),
                    "--out-dir",
                    str(out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            run_dir = Path(tmp) / "run"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--workspace",
                    str(workspace),
                    "--queue",
                    str(out / "v3_provider_fanout_queue.json"),
                    "--out-dir",
                    str(run_dir),
                    "--dry-run",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["summary"], {"failed": 16})

    def test_closeout_quarantines_provider_outputs_and_appends_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            run_dir = Path(tmp) / "run"
            workspace.mkdir()
            output = run_dir / "provider_outputs" / "kimi-01.out.txt"
            audit_dir = run_dir / "llm_dispatch_audit" / "kimi-01"
            output.parent.mkdir(parents=True)
            audit_dir.mkdir(parents=True)
            output.write_text('```json\n[{"verdict":"KEEP_FOR_LOCAL_VERIFICATION"}]\n```\n', encoding="utf-8")
            (audit_dir / "llm_dispatch_1.json").write_text(
                json.dumps(
                    {
                        "provider": "kimi",
                        "model": "kimi-for-coding",
                        "tokens_used": 1234,
                        "outcome": "ok",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            run_manifest = {
                "run_id": "unit",
                "run_dir": str(run_dir),
                "rows": [
                    {
                        "task_id": "kimi-01",
                        "provider": "kimi",
                        "template": "source-extract",
                        "returncode": 0,
                        "status": "ok",
                        "prompt_path": "prompt.md",
                        "provider_output_path": str(output),
                        "kimi_unavailable": True,
                        "standalone_advisory": True,
                        "mcp_receipt": {
                            "present": True,
                            "path": str(workspace / ".auditooor" / "last_mcp_recall.json"),
                            "sha256_16": "abc",
                            "context_pack_id": "ctx",
                            "context_pack_hash": "hash",
                        },
                    }
                ],
            }
            run_manifest_path = run_dir / "v3_provider_fanout_run.json"
            run_manifest_path.write_text(json.dumps(run_manifest), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(CLOSEOUT),
                    "--workspace",
                    str(workspace),
                    "--run",
                    str(run_manifest_path),
                    "--append-learning-ledger",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            closeout = json.loads((run_dir / "fanout_closeout.json").read_text(encoding="utf-8"))
            self.assertEqual(closeout["summary"]["by_status"], {"needs_local_verification": 1})
            self.assertEqual(closeout["summary"]["tokens_by_provider"], {"kimi": 1234})
            self.assertTrue(closeout["rows"][0]["kimi_unavailable"])
            self.assertTrue(closeout["rows"][0]["standalone_advisory"])
            ledger = workspace / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            self.assertTrue(ledger.is_file())
            row = json.loads(ledger.read_text(encoding="utf-8").splitlines()[0])
            self.assertTrue(row["quarantine"])
            self.assertEqual(row["evidence_tier"], "secondary")
            self.assertTrue(row["local_verification_required"])
            self.assertTrue(row["kimi_unavailable"])
            self.assertTrue(row["standalone_advisory"])
            second = subprocess.run(
                [
                    sys.executable,
                    str(CLOSEOUT),
                    "--workspace",
                    str(workspace),
                    "--run",
                    str(run_manifest_path),
                    "--append-learning-ledger",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(len(ledger.read_text(encoding="utf-8").splitlines()), 1)

    def test_closeout_classifies_long_fenced_json_without_truncating_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            run_dir = Path(tmp) / "run"
            workspace.mkdir()
            output = run_dir / "provider_outputs" / "kimi-long.out.txt"
            audit_dir = run_dir / "llm_dispatch_audit" / "kimi-long"
            output.parent.mkdir(parents=True)
            audit_dir.mkdir(parents=True)
            payload = {"advisory_candidates": [{"candidate_id": "c1", "notes": "x" * 30000}]}
            output.write_text("```json\n" + json.dumps(payload) + "\n```\n", encoding="utf-8")
            (audit_dir / "llm_dispatch_1.json").write_text(
                json.dumps(
                    {
                        "provider": "kimi",
                        "model": "kimi-for-coding",
                        "tokens_used": 999,
                        "outcome": "ok",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            run_manifest = {
                "run_id": "unit",
                "run_dir": str(run_dir),
                "rows": [
                    {
                        "task_id": "kimi-long",
                        "provider": "kimi",
                        "template": "source-extract",
                        "returncode": 0,
                        "status": "ok",
                        "prompt_path": "prompt.md",
                        "provider_output_path": str(output),
                        "mcp_receipt": {
                            "present": True,
                            "path": str(workspace / ".auditooor" / "last_mcp_recall.json"),
                            "sha256_16": "abc",
                        },
                    }
                ],
            }
            run_manifest_path = run_dir / "v3_provider_fanout_run.json"
            run_manifest_path.write_text(json.dumps(run_manifest), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(CLOSEOUT),
                    "--workspace",
                    str(workspace),
                    "--run",
                    str(run_manifest_path),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            closeout = json.loads((run_dir / "fanout_closeout.json").read_text(encoding="utf-8"))
            self.assertEqual(closeout["rows"][0]["output_shape"], "json")
            self.assertEqual(closeout["rows"][0]["status"], "needs_local_verification")

    def test_closeout_ignores_provider_self_attested_local_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "ws"
            run_dir = Path(tmp) / "run"
            workspace.mkdir()
            output = run_dir / "provider_outputs" / "kimi-self.out.txt"
            audit_dir = run_dir / "llm_dispatch_audit" / "kimi-self"
            output.parent.mkdir(parents=True)
            audit_dir.mkdir(parents=True)
            output.write_text(
                json.dumps({"local_verification_accepted": True, "advisory_candidates": []}) + "\n",
                encoding="utf-8",
            )
            (audit_dir / "llm_dispatch_1.json").write_text(
                json.dumps({"provider": "kimi", "model": "kimi-for-coding", "tokens_used": 1}) + "\n",
                encoding="utf-8",
            )
            run_manifest = {
                "run_id": "unit",
                "run_dir": str(run_dir),
                "campaign_id": "unit-campaign",
                "rows": [
                    {
                        "task_id": "kimi-self",
                        "provider": "kimi",
                        "template": "source-extract",
                        "returncode": 0,
                        "status": "ok",
                        "prompt_path": "prompt.md",
                        "provider_output_path": str(output),
                        "mcp_receipt": {"present": True, "path": "receipt.json", "sha256_16": "abc"},
                    }
                ],
            }
            run_manifest_path = run_dir / "v3_provider_fanout_run.json"
            run_manifest_path.write_text(json.dumps(run_manifest), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(CLOSEOUT),
                    "--workspace",
                    str(workspace),
                    "--run",
                    str(run_manifest_path),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            closeout = json.loads((run_dir / "fanout_closeout.json").read_text(encoding="utf-8"))
            self.assertEqual(closeout["campaign_id"], "unit-campaign")
            self.assertEqual(closeout["rows"][0]["status"], "needs_local_verification")


class V3ProviderFanoutSliceMakefileTests(unittest.TestCase):
    def _makefile_text(self) -> str:
        return MAKEFILE.read_text(encoding="utf-8", errors="replace")

    def _target_recipe(self, target: str) -> str:
        lines = self._makefile_text().splitlines()
        start = None
        for index, line in enumerate(lines):
            if line == f"{target}:":
                start = index + 1
                break
        self.assertIsNotNone(start, f"{target}: target missing from Makefile")
        recipe: list[str] = []
        for line in lines[start:]:
            if line and not line.startswith("\t") and not line.startswith(" ") and ":" in line:
                break
            recipe.append(line)
        return "\n".join(recipe)

    def test_slice_target_is_phony(self) -> None:
        makefile = self._makefile_text()
        self.assertIn(".PHONY:", makefile)
        self.assertIn("v3-provider-fanout-slice", makefile)

    def test_slice_chains_required_targets_in_order(self) -> None:
        recipe = self._target_recipe("v3-provider-fanout-slice")
        required = [
            "v3-provider-fanout-queue",
            "v3-provider-fanout-run",
            "v3-provider-fanout-closeout",
            "v3-provider-local-verification-queue",
            "v3-provider-local-verify",
            "v3-provider-learning-compiler",
            "v3-provider-campaign-completeness-gate",
            "provider-fanout-discipline-check",
        ]
        positions = [recipe.index(item) for item in required]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("ENFORCE_IF_ARTIFACTS=1", recipe)
        self.assertIn("STRICT=1", recipe)

    def test_run_target_exposes_minimax_standalone_advisory_flag(self) -> None:
        recipe = self._target_recipe("v3-provider-fanout-run")
        self.assertIn("MINIMAX_STANDALONE_ADVISORY", recipe)
        self.assertIn("--minimax-standalone-advisory", recipe)

    def test_slice_branches_live_vs_dry_run(self) -> None:
        recipe = self._target_recipe("v3-provider-fanout-slice")
        self.assertIn('if [ "$(LIVE)" = "1" ]', recipe)
        self.assertIn("LIVE=1", recipe)
        self.assertIn("DRY_RUN=1", recipe)
        self.assertIn("set -e", recipe)


if __name__ == "__main__":
    unittest.main()
