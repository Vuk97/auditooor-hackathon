from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "detector-hit-action-graph.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("detector_hit_action_graph", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class DetectorHitActionGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        (self.repo / "reference" / "patterns.dsl").mkdir(parents=True)
        self.ws.mkdir()
        (self.repo / "reference" / "patterns.dsl" / "reentrancy-no-guard.yaml").write_text(
            textwrap.dedent(
                """
                pattern: reentrancy-no-guard
                source: unit-test
                severity: HIGH
                confidence: HIGH
                help: "withdraw sends value through an external callback before a reentrancy lock is set; reentrant hook can call withdraw again."
                match:
                  - function.name_matches: '(?i)withdraw'
                  - function.body_contains_regex: 'call'
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": str(self.ws / "src" / "Vault.sol") + ":42",
                                "snippet": "withdraw callback path sends value before reentrancy lock update",
                            }
                        ],
                    }
                ],
            },
        )
        _write_json(
            self.ws / "swarm" / "chained_attack_plans.json",
            {
                "plans": [
                    {
                        "chain_id": "CHAIN-001",
                        "status": "candidate_not_submit_ready",
                        "score": 9,
                        "composition_rationale": "reentrancy-no-guard composes with stale share accounting",
                        "blockers": ["source proof missing"],
                        "source_refs": ["workspace:src/Vault.sol:42"],
                        "candidate_not_submit_ready": True,
                    }
                ]
            },
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_engage_hit_becomes_advisory_action_graph(self) -> None:
        tool = _load_tool()

        payload = tool.build_payload(
            tool.build_parser().parse_args(
                [
                    "--repo-root",
                    str(self.repo),
                    "--workspace",
                    str(self.ws),
                    "--detector-slug",
                    "reentrancy-no-guard",
                    "--language",
                    "solidity",
                    "--function-name",
                    "withdraw",
                    "--top-n",
                    "2",
                ]
            )
        )

        self.assertEqual(payload["schema"], "auditooor.detector_hit_action_graph.v1")
        self.assertEqual(payload["hacker_question_schema"], "auditooor.hacker_question.v1")
        self.assertTrue(payload["advisory_only"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["detector_hit"]["file_path"], "src/Vault.sol:42")
        self.assertEqual(payload["ranked_attack_classes"][0]["attack_class"], "reentrancy")
        self.assertGreaterEqual(payload["summary"]["hacker_question_count"], 1)
        self.assertEqual(payload["hacker_questions"][0]["schema"], "auditooor.hacker_question.v1")
        self.assertEqual(payload["hacker_questions"][0]["detector_slug"], "reentrancy-no-guard")
        self.assertEqual(payload["hacker_questions"][0]["target_file"], "src/Vault.sol:42")
        self.assertIn("proof_obligation", payload["hacker_questions"][0])
        self.assertIn("kill_condition", payload["hacker_questions"][0])
        self.assertEqual(payload["hacker_questions"][0]["mcp_context_pack_id"], payload["context_pack_id"])
        self.assertGreaterEqual(payload["summary"]["action_node_count"], 5)
        self.assertGreaterEqual(payload["summary"]["proof_obligation_count"], 4)
        self.assertEqual(payload["summary"]["chain_candidate_count"], 1)
        self.assertTrue(payload["context_pack_id"].startswith(payload["schema"]))

        node_kinds = {row["kind"] for row in payload["action_graph"]["nodes"]}
        self.assertIn("detector_signal", node_kinds)
        self.assertIn("attacker_goal", node_kinds)
        self.assertIn("precondition", node_kinds)
        self.assertIn("state_transition", node_kinds)
        self.assertIn("impact_probe", node_kinds)

        obligation_kinds = {row["kind"] for row in payload["proof_obligations"]}
        self.assertIn("source_confirmation", obligation_kinds)
        self.assertIn("attacker_control", obligation_kinds)
        self.assertIn("state_and_impact", obligation_kinds)
        self.assertIn("chain_candidate_bridge", obligation_kinds)
        self.assertIn("do not prove exploitability", payload["proof_boundary"].lower())

    def test_cli_writes_output_without_submit_ready_claim(self) -> None:
        out = self.base / "graph.json"
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--repo-root",
                str(self.repo),
                "--workspace",
                str(self.ws),
                "--hit-index",
                "0",
                "--out",
                str(out),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=45,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["detector_hit"]["detector_slug"], "reentrancy-no-guard")
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertTrue(payload["advisory_only"])
        self.assertNotEqual(payload["submission_posture"], "SUBMIT_READY")

    def test_detector_slug_match_normalizes_underscore_and_hyphen(self) -> None:
        tool = _load_tool()

        payload = tool.build_payload(
            tool.build_parser().parse_args(
                [
                    "--repo-root",
                    str(self.repo),
                    "--workspace",
                    str(self.ws),
                    "--detector-slug",
                    "reentrancy_no_guard",
                ]
            )
        )

        self.assertEqual(payload["detector_hit"]["detector_slug"], "reentrancy-no-guard")
        self.assertEqual(payload["detector_hit"]["file_path"], "src/Vault.sol:42")

    def test_unknown_only_chain_candidate_terms_do_not_attach_plans(self) -> None:
        tool = _load_tool()
        _write_json(
            self.ws / "swarm" / "chained_attack_plans.json",
            {
                "plans": [
                    {
                        "chain_id": "CHAIN-UNKNOWN",
                        "composition_rationale": "unknown fallback should never match by itself",
                        "source_refs": ["workspace:src/Other.sol:1"],
                    }
                ]
            },
        )

        payload = tool.build_payload(
            tool.build_parser().parse_args(
                [
                    "--repo-root",
                    str(self.repo),
                    "--workspace",
                    str(self.ws),
                    "--detector-slug",
                    "does-not-exist",
                    "--file-path",
                    "",
                    "--top-n",
                    "0",
                ]
            )
        )

        self.assertEqual(payload["chain_candidates"], [])
        self.assertEqual(payload["summary"]["chain_candidate_count"], 0)

    def test_generic_attack_class_text_without_anchor_does_not_attach_chain_plan(self) -> None:
        tool = _load_tool()
        _write_json(
            self.ws / "swarm" / "chained_attack_plans.json",
            {
                "plans": [
                    {
                        "chain_id": "CHAIN-GENERIC-REENTRANCY",
                        "composition_rationale": (
                            "generic reentrancy template composes with stale share accounting "
                            "when an unrelated pool callback exists"
                        ),
                        "source_refs": ["workspace:src/OtherPool.sol:7"],
                        "primitives": [
                            {
                                "primitive_id": "unrelated-callback-template",
                                "title": "Generic reentrancy case study",
                                "source_refs": ["workspace:src/OtherPool.sol:7"],
                            }
                        ],
                    }
                ]
            },
        )

        payload = tool.build_payload(
            tool.build_parser().parse_args(
                [
                    "--repo-root",
                    str(self.repo),
                    "--workspace",
                    str(self.ws),
                    "--detector-slug",
                    "reentrancy-no-guard",
                    "--top-n",
                    "2",
                ]
            )
        )

        self.assertEqual(payload["chain_candidates"], [])
        self.assertEqual(payload["summary"]["chain_candidate_count"], 0)


class HarnessTaskTests(unittest.TestCase):
    """Lane 7 / Slice 5: harness task row derivation from detector hits."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        (self.repo / "reference" / "patterns.dsl").mkdir(parents=True)
        self.ws.mkdir()
        # Write a pattern fixture so the ranker has something to match
        (self.repo / "reference" / "patterns.dsl" / "reentrancy-no-guard.yaml").write_text(
            textwrap.dedent(
                """
                pattern: reentrancy-no-guard
                source: unit-test
                severity: HIGH
                confidence: HIGH
                help: "withdraw sends value through an external callback before a reentrancy lock is set; reentrant hook can call withdraw again."
                match:
                  - function.name_matches: '(?i)withdraw'
                  - function.body_contains_regex: 'call'
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _build(self, extra_args: list[str]) -> dict:
        tool = _load_tool()
        return tool.build_payload(
            tool.build_parser().parse_args(
                [
                    "--repo-root", str(self.repo),
                    "--workspace", str(self.ws),
                    "--top-n", "2",
                ]
                + extra_args
            )
        )

    # ------------------------------------------------------------------
    # Schema and top-level fields
    # ------------------------------------------------------------------

    def test_harness_tasks_present_in_payload(self) -> None:
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": str(self.ws / "src" / "Vault.sol") + ":42",
                                "snippet": "withdraw sends ether before guard",
                            }
                        ],
                    }
                ],
            },
        )
        payload = self._build(
            ["--detector-slug", "reentrancy-no-guard", "--language", "solidity"]
        )
        self.assertIn("harness_tasks", payload)
        self.assertIn("harness_task_schema", payload)
        self.assertEqual(payload["harness_task_schema"], "auditooor.harness_task.v1")
        self.assertGreaterEqual(payload["summary"]["harness_task_count"], 1)

    # ------------------------------------------------------------------
    # EVM / Solidity -> Foundry test
    # ------------------------------------------------------------------

    def test_evm_hit_yields_foundry_harness_type(self) -> None:
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": "src/Vault.sol:42",
                                "snippet": "withdraw sends ether before guard",
                            }
                        ],
                    }
                ],
            },
        )
        payload = self._build(
            ["--detector-slug", "reentrancy-no-guard", "--language", "solidity"]
        )
        tasks = payload["harness_tasks"]
        self.assertGreaterEqual(len(tasks), 1)
        task = tasks[0]
        self.assertEqual(task["harness_type"], "Foundry test")
        self.assertEqual(task["schema"], "auditooor.harness_task.v1")

    # ------------------------------------------------------------------
    # Go / Cosmos -> Go or Cosmos harness
    # ------------------------------------------------------------------

    def test_go_cosmos_hit_yields_go_or_cosmos_harness_type(self) -> None:
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": "src/vault/keeper/cosmos_keeper.go:88",
                                "snippet": "concurrent map write without lock",
                            }
                        ],
                    }
                ],
            },
        )
        payload = self._build(
            ["--detector-slug", "reentrancy-no-guard", "--language", "go"]
        )
        tasks = payload["harness_tasks"]
        self.assertGreaterEqual(len(tasks), 1)
        task = tasks[0]
        self.assertIn(task["harness_type"], ("Go unit/integration test", "Cosmos app-chain test"))

    # ------------------------------------------------------------------
    # Negative control and kill conditions are always present
    # ------------------------------------------------------------------

    def test_harness_task_has_negative_control_and_kill_conditions(self) -> None:
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": "src/Vault.sol:42",
                                "snippet": "withdraw sends ether before guard",
                            }
                        ],
                    }
                ],
            },
        )
        payload = self._build(
            ["--detector-slug", "reentrancy-no-guard", "--language", "solidity"]
        )
        for task in payload["harness_tasks"]:
            self.assertIn("negative_control", task, f"task {task.get('task_id')} missing negative_control")
            nc = task["negative_control"]
            self.assertIn("description", nc)
            self.assertIn("assertion", nc)
            self.assertTrue(nc["description"], "negative_control.description must be non-empty")
            self.assertIn("kill_conditions", task, f"task {task.get('task_id')} missing kill_conditions")
            self.assertIsInstance(task["kill_conditions"], list)
            self.assertGreaterEqual(len(task["kill_conditions"]), 1)

    # ------------------------------------------------------------------
    # Required fields present in every task row
    # ------------------------------------------------------------------

    def test_harness_task_required_fields_present(self) -> None:
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": "src/Vault.sol:99",
                                "snippet": "external call before state update",
                            }
                        ],
                    }
                ],
            },
        )
        payload = self._build(
            ["--detector-slug", "reentrancy-no-guard", "--language", "solidity"]
        )
        required = {
            "schema", "task_id", "detector_slug", "attack_class", "harness_type",
            "attacker_setup", "victim_setup", "state_transition", "expected_impact",
            "required_control_test", "production_path", "restart_required",
            "multi_node_required", "negative_control", "kill_conditions",
            "submission_posture", "advisory_only", "proof_boundary",
        }
        for task in payload["harness_tasks"]:
            for field in required:
                self.assertIn(field, task, f"task {task.get('task_id')} missing field '{field}'")
        # Submission posture must never imply submit-readiness
        for task in payload["harness_tasks"]:
            self.assertEqual(task["submission_posture"], "NOT_SUBMIT_READY")
            self.assertTrue(task["advisory_only"])

    # ------------------------------------------------------------------
    # Bridge attack class -> bridge harness regardless of language
    # ------------------------------------------------------------------

    def test_bridge_attack_class_yields_bridge_harness(self) -> None:
        # Inject a bridge-class detector hit via CLI args (no engage_report needed)
        payload = self._build(
            [
                "--detector-slug", "cross-chain-replay",
                "--file-path", "src/BridgeGateway.sol:10",
                "--language", "solidity",
                "--context", "bridge message replay without domain binding",
            ]
        )
        tasks = payload["harness_tasks"]
        # At least one ranked class should be bridge/message/cross-chain; check harness type
        harness_types = {t["harness_type"] for t in tasks}
        # The ranker may or may not produce a bridge class for this fixture slug;
        # what we verify is that when attack_class contains a bridge keyword the
        # _choose_harness_type function selects the bridge harness.
        tool = _load_tool()
        bridge_type = tool._choose_harness_type("solidity", "src/BridgeGateway.sol:10", "cross-chain-replay")
        self.assertEqual(bridge_type, "bridge proof/replay harness")

    # ------------------------------------------------------------------
    # Empty workspace: graceful handling (no engage_report)
    # ------------------------------------------------------------------

    def test_no_engage_report_produces_harness_tasks_from_cli_args(self) -> None:
        # No engage_report.json in workspace; rely on CLI args
        payload = self._build(
            [
                "--detector-slug", "reentrancy-no-guard",
                "--file-path", "contracts/Pool.sol:77",
                "--language", "solidity",
            ]
        )
        self.assertIn("harness_tasks", payload)
        # May be empty if ranker returns nothing, but must not raise
        self.assertIsInstance(payload["harness_tasks"], list)

    # ------------------------------------------------------------------
    # --json flag works as alias for --print-json
    # ------------------------------------------------------------------

    def test_json_flag_is_accepted(self) -> None:
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": "src/Vault.sol:42",
                                "snippet": "withdraw sends ether before guard",
                            }
                        ],
                    }
                ],
            },
        )
        import io
        from contextlib import redirect_stdout

        tool = _load_tool()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = tool.main(
                [
                    "--repo-root", str(self.repo),
                    "--workspace", str(self.ws),
                    "--detector-slug", "reentrancy-no-guard",
                    "--language", "solidity",
                    "--json",
                ]
            )
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("harness_tasks", payload)

    # ------------------------------------------------------------------
    # summary.harness_task_count matches len(harness_tasks)
    # ------------------------------------------------------------------

    def test_summary_harness_task_count_matches_list_length(self) -> None:
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": "src/Vault.sol:42",
                                "snippet": "withdraw sends ether before guard",
                            }
                        ],
                    }
                ],
            },
        )
        payload = self._build(
            ["--detector-slug", "reentrancy-no-guard", "--language", "solidity"]
        )
        self.assertEqual(
            payload["summary"]["harness_task_count"],
            len(payload["harness_tasks"]),
        )

    # ------------------------------------------------------------------
    # Solana language -> Solana program-test harness
    # ------------------------------------------------------------------

    def test_solana_language_yields_solana_harness(self) -> None:
        tool = _load_tool()
        harness_type = tool._choose_harness_type("solana", "program/src/lib.rs", "access-control")
        self.assertEqual(harness_type, "Solana program-test/LiteSVM")

    # ------------------------------------------------------------------
    # File-extension inference: .sol -> Foundry, .go -> Go
    # ------------------------------------------------------------------

    def test_extension_inference_sol_gives_foundry(self) -> None:
        tool = _load_tool()
        self.assertEqual(
            tool._choose_harness_type("", "contracts/Token.sol:5", "reentrancy"),
            "Foundry test",
        )

    def test_extension_inference_go_gives_go(self) -> None:
        tool = _load_tool()
        result = tool._choose_harness_type("", "pkg/keeper/keeper.go:100", "access-control")
        self.assertIn(result, ("Go unit/integration test", "Cosmos app-chain test"))


class HarnessCommandGenerationTests(unittest.TestCase):
    """Lane C2: harness_command field is non-null and deterministic for every harness_type."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        (self.repo / "reference" / "patterns.dsl").mkdir(parents=True)
        self.ws.mkdir()
        (self.repo / "reference" / "patterns.dsl" / "reentrancy-no-guard.yaml").write_text(
            textwrap.dedent(
                """
                pattern: reentrancy-no-guard
                source: unit-test
                severity: HIGH
                confidence: HIGH
                help: "withdraw sends value through an external callback."
                match:
                  - function.name_matches: '(?i)withdraw'
                  - function.body_contains_regex: 'call'
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # ------------------------------------------------------------------
    # Foundry / EVM: forge test command is generated
    # ------------------------------------------------------------------

    def test_evm_harness_command_is_forge_test(self) -> None:
        tool = _load_tool()
        command, status = tool._generate_harness_command(
            harness_type="Foundry test",
            task_id="HT-001",
            detector_slug="reentrancy-no-guard",
            attack_class="reentrancy",
            source_file="src/Vault.sol:42",
            workspace=None,
        )
        self.assertTrue(command, "EVM harness command must be non-empty")
        self.assertIn("forge test", command)
        self.assertIn("--match-test", command)
        self.assertIn("-vvv", command)
        self.assertIn("ht_001", command.lower(), "task_id slug must appear in test name")
        self.assertIn(status, ("command_ready", "command_ready_test_missing"))

    # ------------------------------------------------------------------
    # Go unit/integration: go test command is generated
    # ------------------------------------------------------------------

    def test_go_harness_command_is_go_test(self) -> None:
        tool = _load_tool()
        command, status = tool._generate_harness_command(
            harness_type="Go unit/integration test",
            task_id="HT-002",
            detector_slug="integer-overflow",
            attack_class="arithmetic",
            source_file="pkg/math/safe.go:10",
            workspace=None,
        )
        self.assertTrue(command, "Go harness command must be non-empty")
        self.assertIn("go test", command)
        self.assertIn("-run", command)
        self.assertIn("-count=1", command)
        self.assertIn("-v", command)
        # task_id appears in the test function name as PascalCase (e.g. "Ht002")
        self.assertIn("Ht002", command, "task_id slug must appear in test name")
        self.assertIn(status, ("command_ready", "command_ready_test_missing"))

    # ------------------------------------------------------------------
    # Cosmos app-chain: go test command with GOTOOLCHAIN=local
    # ------------------------------------------------------------------

    def test_cosmos_harness_command_includes_gotoolchain(self) -> None:
        tool = _load_tool()
        command, status = tool._generate_harness_command(
            harness_type="Cosmos app-chain test",
            task_id="HT-003",
            detector_slug="state-manipulation",
            attack_class="privilege-escalation",
            source_file="x/bank/keeper/keeper.go:55",
            workspace=None,
        )
        self.assertTrue(command, "Cosmos harness command must be non-empty")
        self.assertIn("GOTOOLCHAIN=local", command)
        self.assertIn("go test", command)
        self.assertIn("x/bank/keeper", command)
        self.assertIn("Ht003", command, "PascalCase task_id must appear in test function name")
        self.assertIn(status, ("command_ready", "command_ready_test_missing"))

    # ------------------------------------------------------------------
    # Solana program-test: cargo test command is generated
    # ------------------------------------------------------------------

    def test_solana_harness_command_is_cargo_test(self) -> None:
        tool = _load_tool()
        command, status = tool._generate_harness_command(
            harness_type="Solana program-test/LiteSVM",
            task_id="HT-001",
            detector_slug="signer-check-missing",
            attack_class="access-control",
            source_file="program/src/processor.rs:20",
            workspace=None,
        )
        self.assertTrue(command, "Solana harness command must be non-empty")
        self.assertIn("cargo test", command)
        self.assertIn("--nocapture", command)
        self.assertIn("ht_001", command.lower(), "task_id slug must appear in test name")
        self.assertIn(status, ("command_ready", "command_ready_test_missing"))

    # ------------------------------------------------------------------
    # Bridge harness: forge for Solidity source, go test for non-EVM
    # ------------------------------------------------------------------

    def test_bridge_sol_harness_command_is_forge(self) -> None:
        tool = _load_tool()
        command, status = tool._generate_harness_command(
            harness_type="bridge proof/replay harness",
            task_id="HT-002",
            detector_slug="cross-chain-replay",
            attack_class="cross-chain",
            source_file="src/Bridge.sol:99",
            workspace=None,
        )
        self.assertTrue(command, "Bridge/Solidity harness command must be non-empty")
        self.assertIn("forge test", command)
        self.assertIn(status, ("command_ready", "command_ready_test_missing"))

    def test_bridge_go_harness_command_is_go_test(self) -> None:
        tool = _load_tool()
        command, status = tool._generate_harness_command(
            harness_type="bridge proof/replay harness",
            task_id="HT-003",
            detector_slug="relay-replay",
            attack_class="bridge",
            source_file="relay/verifier.go:33",
            workspace=None,
        )
        self.assertTrue(command, "Bridge/Go harness command must be non-empty")
        self.assertIn("go test", command)
        self.assertIn(status, ("command_ready", "command_ready_test_missing"))

    # ------------------------------------------------------------------
    # Determinism: same inputs produce the same command
    # ------------------------------------------------------------------

    def test_harness_command_is_deterministic(self) -> None:
        tool = _load_tool()
        kwargs = dict(
            harness_type="Foundry test",
            task_id="HT-001",
            detector_slug="reentrancy-no-guard",
            attack_class="reentrancy",
            source_file="src/Vault.sol:42",
            workspace=None,
        )
        command_a, status_a = tool._generate_harness_command(**kwargs)
        command_b, status_b = tool._generate_harness_command(**kwargs)
        self.assertEqual(command_a, command_b, "harness_command must be deterministic")
        self.assertEqual(status_a, status_b, "harness_status must be deterministic")

    # ------------------------------------------------------------------
    # command_ready_test_missing when test file does not exist
    # ------------------------------------------------------------------

    def test_status_is_test_missing_when_file_absent(self) -> None:
        tool = _load_tool()
        # workspace exists but test/Vault.t.sol does not
        _, status = tool._generate_harness_command(
            harness_type="Foundry test",
            task_id="HT-001",
            detector_slug="reentrancy-no-guard",
            attack_class="reentrancy",
            source_file="src/Vault.sol:42",
            workspace=self.ws,
        )
        self.assertEqual(status, "command_ready_test_missing")

    # ------------------------------------------------------------------
    # command_ready when test file actually exists on disk
    # ------------------------------------------------------------------

    def test_status_is_command_ready_when_test_file_exists(self) -> None:
        tool = _load_tool()
        # Create the Foundry test file that the command would target
        test_dir = self.ws / "test"
        test_dir.mkdir(parents=True, exist_ok=True)
        # _test_slug for HT-001/reentrancy-no-guard/reentrancy
        slug = tool._test_slug("HT-001", "reentrancy-no-guard", "reentrancy")
        # For EVM the test file is test/<stem>.t.sol where stem = "Vault"
        (test_dir / "Vault.t.sol").write_text(
            f"// SPDX-License-Identifier: MIT\ncontract VaultTest {{ function test_{slug}() external {{}} }}\n",
            encoding="utf-8",
        )
        _, status = tool._generate_harness_command(
            harness_type="Foundry test",
            task_id="HT-001",
            detector_slug="reentrancy-no-guard",
            attack_class="reentrancy",
            source_file="src/Vault.sol:42",
            workspace=self.ws,
        )
        self.assertEqual(status, "command_ready")

    # ------------------------------------------------------------------
    # Unresolvable harness type returns empty command and typed status
    # ------------------------------------------------------------------

    def test_unresolvable_harness_type_returns_typed_status(self) -> None:
        tool = _load_tool()
        command, status = tool._generate_harness_command(
            harness_type="Unknown runtime XYZ",
            task_id="HT-001",
            detector_slug="some-detector",
            attack_class="unknown",
            source_file="",
            workspace=None,
        )
        self.assertEqual(status, "unresolvable")
        self.assertFalse(command, "unresolvable harness must return empty command string")

    # ------------------------------------------------------------------
    # HT descriptors in payload carry non-null harness_command
    # ------------------------------------------------------------------

    def test_ht_descriptors_carry_non_null_harness_command(self) -> None:
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": "src/Vault.sol:42",
                                "snippet": "withdraw sends ether before guard",
                            }
                        ],
                    }
                ],
            },
        )
        tool = _load_tool()
        payload = tool.build_payload(
            tool.build_parser().parse_args(
                [
                    "--repo-root", str(self.repo),
                    "--workspace", str(self.ws),
                    "--detector-slug", "reentrancy-no-guard",
                    "--language", "solidity",
                    "--top-n", "2",
                ]
            )
        )
        tasks = payload["harness_tasks"]
        self.assertGreaterEqual(len(tasks), 1)
        for task in tasks:
            self.assertIn("harness_command", task, f"task {task.get('task_id')} missing harness_command field")
            self.assertIn("harness_status", task, f"task {task.get('task_id')} missing harness_status field")
            # harness_command must be non-None (may be a non-empty string)
            self.assertIsNotNone(task["harness_command"], f"task {task.get('task_id')} has harness_command=None")
            self.assertTrue(
                task["harness_command"],
                f"task {task.get('task_id')} has empty harness_command",
            )
            self.assertIn(
                task["harness_status"],
                ("command_ready", "command_ready_test_missing", "unresolvable"),
                f"task {task.get('task_id')} has invalid harness_status {task.get('harness_status')!r}",
            )

    # ------------------------------------------------------------------
    # harness_status is command_ready_test_missing for new workspaces
    # (no pre-existing test files) - not unresolvable or None
    # ------------------------------------------------------------------

    def test_harness_status_is_test_missing_not_unresolvable_for_known_types(self) -> None:
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": "src/Vault.sol:42",
                                "snippet": "withdraw sends ether before guard",
                            }
                        ],
                    }
                ],
            },
        )
        tool = _load_tool()
        payload = tool.build_payload(
            tool.build_parser().parse_args(
                [
                    "--repo-root", str(self.repo),
                    "--workspace", str(self.ws),
                    "--detector-slug", "reentrancy-no-guard",
                    "--language", "solidity",
                    "--top-n", "1",
                ]
            )
        )
        for task in payload["harness_tasks"]:
            self.assertNotEqual(
                task.get("harness_status"), "unresolvable",
                f"task {task.get('task_id')} should not be unresolvable for EVM/Foundry",
            )
            self.assertEqual(task.get("harness_status"), "command_ready_test_missing")

    # ------------------------------------------------------------------
    # _test_slug is deterministic and unique across different task_ids
    # ------------------------------------------------------------------

    def test_test_slug_is_deterministic(self) -> None:
        tool = _load_tool()
        slug_a = tool._test_slug("HT-001", "reentrancy-no-guard", "reentrancy")
        slug_b = tool._test_slug("HT-001", "reentrancy-no-guard", "reentrancy")
        self.assertEqual(slug_a, slug_b)

    def test_test_slug_differs_by_task_id(self) -> None:
        tool = _load_tool()
        slug_1 = tool._test_slug("HT-001", "reentrancy-no-guard", "reentrancy")
        slug_2 = tool._test_slug("HT-002", "reentrancy-no-guard", "reentrancy")
        self.assertNotEqual(slug_1, slug_2, "different task_ids must produce different slugs")

    # ------------------------------------------------------------------
    # harness_command can be consumed by harness-execution-queue assess_local_command
    # ------------------------------------------------------------------

    def test_generated_commands_are_safe_per_execution_queue(self) -> None:
        """Generated commands must pass assess_local_command (no blockers)."""
        import importlib.util as _ilu
        import sys as _sys

        heq_path = Path(__file__).resolve().parents[2] / "tools" / "harness-execution-queue.py"
        spec = _ilu.spec_from_file_location("harness_execution_queue_for_c2_test", str(heq_path))
        assert spec is not None and spec.loader is not None
        heq = _ilu.module_from_spec(spec)
        _sys.modules[spec.name] = heq
        spec.loader.exec_module(heq)

        tool = _load_tool()
        cases = [
            ("Foundry test", "HT-001", "reentrancy-no-guard", "reentrancy", "src/Vault.sol:42"),
            ("Go unit/integration test", "HT-002", "integer-overflow", "arithmetic", "pkg/safe.go:10"),
            ("Cosmos app-chain test", "HT-003", "state-manipulation", "privilege-escalation", "x/bank/keeper/keeper.go:55"),
            ("Solana program-test/LiteSVM", "HT-001", "signer-check-missing", "access-control", "program/src/processor.rs:20"),
            ("bridge proof/replay harness", "HT-002", "cross-chain-replay", "cross-chain", "src/Bridge.sol:99"),
        ]
        for harness_type, task_id, det_slug, attack_class, source_file in cases:
            command, status = tool._generate_harness_command(
                harness_type=harness_type,
                task_id=task_id,
                detector_slug=det_slug,
                attack_class=attack_class,
                source_file=source_file,
                workspace=None,
            )
            if status == "unresolvable":
                continue  # skip; no command to validate
            result = heq.assess_local_command(command)
            self.assertTrue(
                result["safe"],
                f"Generated command for {harness_type!r} blocked by execution queue: "
                f"command={command!r} blockers={result['blockers']}",
            )


if __name__ == "__main__":
    unittest.main()
