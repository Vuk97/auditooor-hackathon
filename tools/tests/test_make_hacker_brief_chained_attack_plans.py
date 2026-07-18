#!/usr/bin/env python3
"""Hermetic coverage for `make hacker-brief` -> `make chained-attack-plans`.

The goal here is narrow:

* prove the Makefile recipe for `hacker-brief` targets the canonical
  `.auditooor/hacker_brief.md` path and requests the JSON sidecar.
* prove a live `make hacker-brief` invocation writes
  `.auditooor/hacker_brief.md.json`.
* prove `make chained-attack-plans` consumes only the canonical sidecar path,
  ignoring stale lane-specific siblings such as `hacker_brief_stale.md.json`.
* prove `make proof-obligation-queue` consumes the canonical brief/chain-plan
  outputs and emits the bounded proof-task queue.

Hermeticity:

* the live test runs against a tempfile workspace, never `~/audits/*`.
* a PATH-scoped `python3` shim intercepts only the augmenter call and emits a
  deterministic sidecar; every other Python invocation delegates to the real
  interpreter so the real planner still runs.
* no network, no GitHub, no Spark workspace, no dependency installs.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


def _run_make(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", *args],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_python3_shim(bin_dir: Path) -> Path:
    """Write a `python3` shim that stubs only the augmenter invocation."""
    shim_path = bin_dir / "python3"
    shim_path.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json
            import os
            import sys
            from pathlib import Path

            REAL_PYTHON = {sys.executable!r}


            def _arg_value(flag: str) -> str | None:
                try:
                    idx = sys.argv.index(flag)
                except ValueError:
                    return None
                if idx + 1 >= len(sys.argv):
                    return None
                return sys.argv[idx + 1]


            script = Path(sys.argv[1]).name if len(sys.argv) > 1 else ""
            if script == "agent-prompt-hacker-augmenter.py":
                out_arg = _arg_value("--out")
                lane_id = _arg_value("--lane-id") or _arg_value("--lane") or "H1-test"
                files_arg = _arg_value("--files") or ""
                files = [item.strip() for item in files_arg.split(",") if item.strip()]
                out_path = Path(out_arg).expanduser().resolve() if out_arg else Path.cwd() / "hacker_brief.md"
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(
                    "# Hacker Brief\\n\\n- Q-DET-current-detector\\n",
                    encoding="utf-8",
                )
                payload = {{
                    "schema": "auditooor.hacker_brief_augmenter.v1",
                    "lane_id": lane_id,
                    "workspace": "<workspace>",
                    "files": files,
                    "sections": {{
                        "sec13_question_list": {{
                            "items": [
                                {{
                                    "id": "Q-DET-current-detector",
                                    "text": "Was current detector investigated?",
                                    "evidence": "current evidence",
                                }}
                            ]
                        }}
                    }},
                }}
                (Path(str(out_path) + ".json")).write_text(
                    json.dumps(payload, indent=2) + "\\n",
                    encoding="utf-8",
                )
                print(str(out_path))
                raise SystemExit(0)

            os.execv(REAL_PYTHON, [REAL_PYTHON, *sys.argv[1:]])
            """
        ),
        encoding="utf-8",
    )
    shim_path.chmod(shim_path.stat().st_mode | stat.S_IXUSR)
    return shim_path


class MakeHackerBriefChainedAttackPlansTest(unittest.TestCase):
    def test_make_hacker_brief_dry_run_targets_canonical_sidecar_path(self) -> None:
        ws = "/tmp/hermetic-hacker-brief"
        proc = _run_make(
            [
                "-n",
                "hacker-brief",
                f"WS={ws}",
                "LANE=H1-vault",
                "FILES=src/Vault.sol",
            ]
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("tools/agent-prompt-hacker-augmenter.py", proc.stdout)
        self.assertIn(f"--out {ws}/.auditooor/hacker_brief.md", proc.stdout)
        self.assertIn("--json-out", proc.stdout)
        self.assertIn("tools/hackerman-brief-for-lane.py", proc.stdout)
        self.assertIn(f"{ws}/.auditooor/hacker_brief.hackerman.json", proc.stdout)

    def test_make_proof_obligation_queue_dry_run_targets_canonical_output(self) -> None:
        ws = "/tmp/hermetic-proof-obligation-queue"
        proc = _run_make(["-n", "proof-obligation-queue", f"WS={ws}"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("set -e", proc.stdout)
        self.assertIn("tools/proof-obligation-queue.py", proc.stdout)
        self.assertIn(f'--workspace "{ws}"', proc.stdout)
        self.assertIn(f'out_path="{ws}/.auditooor/proof_obligation_queue.json"', proc.stdout)
        self.assertIn("tools/proof-queue-freshness-marker.py", proc.stdout)
        self.assertIn("--mode mark-fresh", proc.stdout)
        self.assertIn("--reason \"proof-obligation-queue completed directly\"", proc.stdout)

        with_graph = _run_make(
            [
                "-n",
                "proof-obligation-queue",
                f"WS={ws}",
                f"DETECTOR_ACTION_GRAPH={ws}/.auditooor/detector_action_graph.json",
            ]
        )
        self.assertEqual(with_graph.returncode, 0, with_graph.stderr)
        self.assertIn(
            f'--detector-action-graph "{ws}/.auditooor/detector_action_graph.json"',
            with_graph.stdout,
        )

    def test_make_chained_attack_plans_dry_run_does_not_mask_tool_failure(self) -> None:
        ws = "/tmp/hermetic-chained-attack-plans"
        proc = _run_make(["-n", "chained-attack-plans", f"WS={ws}", "MAX_PLANS=2"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("set -e", proc.stdout)
        self.assertIn("tools/chained-attack-planner.py", proc.stdout)
        self.assertIn(f'--workspace "{ws}"', proc.stdout)
        self.assertIn(f'json_out="{ws}/swarm/chained_attack_plans.json"', proc.stdout)
        self.assertIn(f'md_out="{ws}/swarm/chained_attack_plans.md"', proc.stdout)
        self.assertIn('--out "$json_out"', proc.stdout)
        self.assertIn('--markdown-out "$md_out"', proc.stdout)
        self.assertIn('--max-plans "2"', proc.stdout)

    def test_make_audit_hacker_logic_bridge_dry_run_targets_action_graph_and_queue(self) -> None:
        ws = "/tmp/hermetic-audit-hacker-logic-bridge"
        proc = _run_make(
            [
                "-n",
                "audit-hacker-logic-bridge",
                f"WS={ws}",
                "MAX_HITS=2",
                "PRIORITY_MODE=dydx",
                "TARGET_REPO=dydxprotocol/v4-chain",
                "LANGUAGE=go",
            ]
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("tools/audit-hacker-logic-bridge.py", proc.stdout)
        self.assertIn(f'--workspace "{ws}"', proc.stdout)
        self.assertIn('--max-hits "2"', proc.stdout)
        self.assertIn('--priority-mode "dydx"', proc.stdout)
        self.assertIn('--target-repo "dydxprotocol/v4-chain"', proc.stdout)
        self.assertIn('--language "go"', proc.stdout)
        self.assertIn("audit_hacker_logic_bridge.json", proc.stdout)
        self.assertIn("tools/proof-queue-freshness-marker.py", proc.stdout)
        self.assertIn("--reason \"audit-hacker-logic-bridge completed directly\"", proc.stdout)

    def test_detector_action_graph_mcp_feed_dry_run_calls_vault_context(self) -> None:
        ws = "/tmp/hermetic-detector-action-graph-mcp"
        proc = _run_make(
            [
                "-n",
                "detector-action-graph-mcp-feed",
                f"WS={ws}",
                "DETECTOR=reentrancy-no-guard",
                "FILE=src/Vault.sol:42",
                "FUNC=withdraw",
                "LANGUAGE=solidity",
            ]
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("vault_detector_action_graph_context", proc.stdout)
        self.assertIn('"workspace_path": sys.argv[1]', proc.stdout)
        self.assertIn('"detector_slug": sys.argv[2]', proc.stdout)
        self.assertIn(f'"{ws}"', proc.stdout)
        self.assertIn('"reentrancy-no-guard"', proc.stdout)
        self.assertIn('"src/Vault.sol:42"', proc.stdout)
        self.assertIn('"withdraw"', proc.stdout)
        self.assertIn('"solidity"', proc.stdout)

    def test_chained_attack_plan_mcp_feed_dry_run_calls_vault_context(self) -> None:
        ws = "/tmp/hermetic-chained-plan-mcp"
        proc = _run_make(
            [
                "-n",
                "chained-attack-plan-mcp-feed",
                f"WS={ws}",
                "MAX_PLANS=2",
                f"CHAIN_PLAN={ws}/swarm/custom_chained_attack_plans.json",
            ]
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("vault_chained_attack_plan_context", proc.stdout)
        self.assertIn('"workspace_path": sys.argv[1]', proc.stdout)
        self.assertIn('"max_plans": int(sys.argv[2])', proc.stdout)
        self.assertIn('"chain_plan_path": chain_plan', proc.stdout)
        self.assertIn(f'"{ws}"', proc.stdout)
        self.assertIn('"2"', proc.stdout)
        self.assertIn(f'"{ws}/swarm/custom_chained_attack_plans.json"', proc.stdout)

    def test_chained_attack_plan_mcp_feed_requires_workspace(self) -> None:
        proc = _run_make(["chained-attack-plan-mcp-feed"])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("WS=<workspace> required", proc.stdout + proc.stderr)

    def test_detector_proof_context_dry_run_calls_vault_context(self) -> None:
        ws = "/tmp/hermetic-detector-proof-context"
        proc = _run_make(
            [
                "-n",
                "detector-proof-context",
                f"WS={ws}",
                "DETECTOR=withdraw-reentrancy-no-guard",
                "STATUS=blocked",
                "PROOF_ONLY=1",
                "LIMIT=3",
            ]
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("vault_solidity_detector_proof_context", proc.stdout)
        self.assertIn('"workspace_path": sys.argv[1]', proc.stdout)
        self.assertIn('"limit": int(sys.argv[2])', proc.stdout)
        self.assertIn('"detector_slug": detector', proc.stdout)
        self.assertIn('"status": status', proc.stdout)
        self.assertIn('"proof_only": proof_only.lower()', proc.stdout)
        self.assertIn(f'"{ws}"', proc.stdout)
        self.assertIn('"3"', proc.stdout)
        self.assertIn('"withdraw-reentrancy-no-guard"', proc.stdout)
        self.assertIn('"blocked"', proc.stdout)
        self.assertIn('"1"', proc.stdout)
        self.assertIn("ADVISORY READ-ONLY CONTEXT", proc.stdout)
        self.assertIn("proof_obligation_queue.freshness.json", proc.stdout)
        self.assertIn("freshness_status=", proc.stdout)
        self.assertIn("advisory-only", proc.stdout)

    def test_detector_proof_context_requires_workspace(self) -> None:
        proc = _run_make(["detector-proof-context"])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("WS=<workspace> required", proc.stdout + proc.stderr)

    def test_detector_proof_context_requires_detector_or_all(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mk-detector-proof-context-") as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()

            proc = _run_make(["detector-proof-context", f"WS={ws}"])

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("DETECTOR=<slug> or ALL=1 required", proc.stdout + proc.stderr)

    def test_make_audit_recipe_wires_proof_queue_freshness_marker(self) -> None:
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        self.assertIn("tools/proof-queue-freshness-marker.py", makefile)
        self.assertIn("--mode mark-stale", makefile)
        self.assertIn("--mode mark-fresh", makefile)
        self.assertIn("audit-hacker-logic-bridge failed during make audit", makefile)
        self.assertIn("audit-hacker-logic-bridge completed during make audit", makefile)
        self.assertIn("proof_obligation_queue.freshness.json", makefile)
        short_circuit_block = makefile.split("if [ $$marker_rc -eq 0 ]", 1)[1].split(
            "if [ $$marker_rc -ge 2 ]", 1
        )[0]
        self.assertIn("audit-hacker-logic-bridge WS=", short_circuit_block)
        self.assertIn("audit-hacker-logic-bridge failed during make audit freshness short-circuit", short_circuit_block)
        self.assertIn(
            "audit-hacker-logic-bridge completed during make audit freshness short-circuit",
            short_circuit_block,
        )
        self.assertIn("refreshed memory and hacker queue", short_circuit_block)

    def test_live_make_hacker_brief_and_chained_attack_plans_use_canonical_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mk-hacker-brief-") as tmp:
            tmp_path = Path(tmp)
            ws = tmp_path / "ws"
            ws.mkdir()
            (ws / ".auditooor").mkdir()
            (ws / "swarm").mkdir()

            _write_json(
                ws / ".auditooor" / "exploit_memory_brief.json",
                {
                    "schema": "auditooor.exploit_memory_brief.v1",
                    "workspace_path": str(ws),
                    "angles": [
                        {
                            "angle_id": "angle-001",
                            "title": "withdraw accounting drift",
                            "protocol_family": "vault",
                            "target_files": ["src/Vault.sol"],
                            "source_refs": ["workspace:src/Vault.sol:10"],
                            "live_prerequisites": [],
                            "hypothesis": "Check whether withdraw state can compose with detector signal.",
                            "attack_surface": "src/Vault.sol",
                            "ranking_rationale": "score=4 source_signal=2",
                            "prior_outcome_signal": {
                                "accepted_count": 0,
                                "duplicate_count": 0,
                                "rejected_count": 0,
                                "sample_size": 0,
                            },
                            "nearest_prior_workspaces": [],
                            "duplicate_guard": {
                                "status": "clear",
                                "material_distinction": "",
                                "evidence_chain": ["repo:reference/outcomes.jsonl"],
                            },
                            "oos_guard": {
                                "status": "scope_artifact_present_manual_review",
                                "clause_refs": ["workspace:SCOPE.md"],
                                "rationale": "Scope artifact present; per-finding OOS gate still required.",
                            },
                            "proof_prerequisites": [],
                            "required_artifacts_for_high_critical": [],
                            "harness_failure_refs": [],
                            "knowledge_gap_refs": [],
                            "detector_saturation": 1,
                            "source_signal_score": 2.0,
                            "evidence_chain": ["workspace:src/Vault.sol:10"],
                            "confidence": "medium",
                            "sample_size": 0,
                            "last_validated_at": "2026-05-12",
                            "counter_examples": [],
                            "recommended_next_command": "collect source proof",
                            "not_submit_ready_until": ["pre-submit gate passes", "proof artifacts execute"],
                            "outcome_semantics": {
                                "unknown_reason_declines_learning_scope": "platform_base_rate_only",
                                "cause_learning_allowed": False,
                            },
                        }
                    ],
                },
            )
            _write_json(
                ws / ".auditooor" / "hacker_brief_stale.md.json",
                {
                    "schema": "auditooor.hacker_brief_augmenter.v1",
                    "lane_id": "stale",
                    "files": ["src/Stale.sol"],
                    "sections": {
                        "sec13_question_list": {
                            "items": [
                                {
                                    "id": "Q-DET-stale-detector",
                                    "text": "Was stale detector investigated?",
                                    "evidence": "stale evidence",
                                }
                            ]
                        }
                    },
                },
            )

            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            _write_python3_shim(bin_dir)

            env = dict(os.environ)
            env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")

            hacker_brief = _run_make(
                [
                    "hacker-brief",
                    f"WS={ws}",
                    "LANE=H1-vault",
                    "FILES=src/Vault.sol",
                ],
                env=env,
            )
            self.assertEqual(
                hacker_brief.returncode,
                0,
                f"hacker-brief failed\nstdout:\n{hacker_brief.stdout}\nstderr:\n{hacker_brief.stderr}",
            )

            canonical_sidecar = ws / ".auditooor" / "hacker_brief.md.json"
            hackerman_sidecar = ws / ".auditooor" / "hacker_brief.hackerman.json"
            self.assertTrue(canonical_sidecar.is_file(), "canonical hacker brief sidecar missing")
            self.assertTrue(hackerman_sidecar.is_file(), "indexed hackerman brief sidecar missing")
            self.assertTrue((ws / ".auditooor" / "hacker_brief.md").is_file(), "markdown brief missing")
            sidecar_payload = json.loads(canonical_sidecar.read_text(encoding="utf-8"))
            self.assertEqual(sidecar_payload["lane_id"], "H1-vault")
            self.assertEqual(sidecar_payload["files"], ["src/Vault.sol"])
            hackerman_payload = json.loads(hackerman_sidecar.read_text(encoding="utf-8"))
            self.assertEqual(hackerman_payload["schema"], "auditooor.hackerman.brief_for_lane.v1")
            markdown_brief = (ws / ".auditooor" / "hacker_brief.md").read_text(encoding="utf-8")
            self.assertIn("# Hacker Brief", markdown_brief)
            self.assertIn("# Hackerman Brief - H1-vault", markdown_brief)

            chained = _run_make(["chained-attack-plans", f"WS={ws}"], env=env)
            self.assertEqual(
                chained.returncode,
                0,
                f"chained-attack-plans failed\nstdout:\n{chained.stdout}\nstderr:\n{chained.stderr}",
            )

            out_path = ws / "swarm" / "chained_attack_plans.json"
            self.assertTrue(out_path.is_file(), "planner output missing")
            payload = json.loads(out_path.read_text(encoding="utf-8"))

            self.assertEqual(payload["summary"]["hacker_brief_qdet_count"], 1)
            self.assertEqual(payload["summary"]["plan_count"], 1)
            plan = payload["plans"][0]
            self.assertIn("shared_files:src/Vault.sol", plan["shared_evidence"])
            self.assertTrue(
                any(item["source_kind"] == "hacker_brief_qdet" for item in plan["primitives"])
            )
            self.assertIn(
                "hacker-brief detector question Q-DET-current-detector is unanswered",
                plan["blockers"],
            )

            rendered = json.dumps(payload, sort_keys=True)
            self.assertIn("current-detector", rendered)
            self.assertNotIn("stale-detector", rendered)

            proof_queue = _run_make(["proof-obligation-queue", f"WS={ws}"], env=env)
            self.assertEqual(
                proof_queue.returncode,
                0,
                f"proof-obligation-queue failed\nstdout:\n{proof_queue.stdout}\nstderr:\n{proof_queue.stderr}",
            )

            queue_path = ws / ".auditooor" / "proof_obligation_queue.json"
            self.assertTrue(queue_path.is_file(), "proof obligation queue output missing")
            queue_payload = json.loads(queue_path.read_text(encoding="utf-8"))
            self.assertEqual(queue_payload["summary"]["question_tasks"], 2)
            self.assertGreaterEqual(queue_payload["summary"]["chain_blocker_tasks"], 1)
            self.assertEqual(queue_payload["summary"]["detector_action_graph_tasks"], 0)
            self.assertEqual(
                queue_payload["summary"]["task_count"],
                queue_payload["summary"]["question_tasks"] + queue_payload["summary"]["chain_blocker_tasks"],
            )

            task_rendered = json.dumps(queue_payload, sort_keys=True)
            self.assertIn("Q-DET-current-detector", task_rendered)
            self.assertIn("CHAIN-001", task_rendered)
            self.assertNotIn("Q-DET-stale-detector", task_rendered)


if __name__ == "__main__":
    unittest.main()
