#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "harness-binding-manifest.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("harness_binding_manifest", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


def _write_file(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class HarnessBindingManifestTest(unittest.TestCase):
    def test_candidate_judgment_filter_allows_only_proof_ready_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            packet = workspace / "candidate_judgment_packet.json"
            packet.write_text(
                json.dumps(
                    {
                        "packets": [
                            {
                                "candidate_id": "EQ-READY",
                                "proof_readiness": {"state": "proof_ready"},
                            },
                            {
                                "candidate_id": "EQ-BLOCKED",
                                "proof_readiness": {"state": "blocked"},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            rows = [
                {
                    "row_id": "EQ-BLOCKED",
                    "title": "blocked",
                    "status": "ready_executable_binding",
                    "harness_family": "forge_invariant",
                },
                {
                    "row_id": "EQ-READY",
                    "title": "ready",
                    "status": "ready_executable_binding",
                    "harness_family": "forge_invariant",
                },
            ]

            manifest = MOD.build_manifest(
                rows,
                workspace=workspace,
                candidate_judgment_path=packet,
            )

        self.assertEqual(manifest["input_row_count"], 2)
        self.assertEqual(manifest["candidate_judgment_filter"], "proof_ready_only")
        self.assertEqual(manifest["candidate_judgment_eligible_count"], 1)
        self.assertEqual([row["row_id"] for row in manifest["rows"]], ["EQ-READY"])

    def test_exact_harness_plan_is_ready_and_derives_generated_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "src" / "Vault.sol", "contract Vault {}\n")
            _write_file(
                workspace / "poc-tests-poly_clob_fill_01" / "test" / "Invariant_POLY_CLOB_FILL_01.t.sol",
                "contract Invariant_POLY_CLOB_FILL_01 {}\n",
            )
            manifest = MOD.build_manifest(
                [
                    {
                        "row_id": "POLY-CLOB-FILL-01",
                        "title": "Exact forge harness",
                        "harness_family": "forge_invariant",
                        "compile_command": "FOUNDRY_PROFILE=invariants forge test --match-contract Invariant_POLY_CLOB_FILL_01 -vv",
                        "source_refs": ["src/Vault.sol:42"],
                        "target_entrypoint": "src/Vault.sol:42",
                        "setup_template": "contract Setup {}",
                        "required_fixtures": ["clob_order_lifecycles"],
                        "impact_contract_id": "impact-poly-clob-fill-01",
                    }
                ],
                workspace=workspace,
            )

        self.assertEqual(manifest["row_count"], 1)
        row = manifest["rows"][0]
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertTrue(row["has_executable_harness_command"])
        self.assertEqual(row["execution_contract"]["schema"], MOD.EXECUTION_CONTRACT_SCHEMA)
        self.assertEqual(row["execution_contract"]["claim"], "runnable_harness")
        self.assertTrue(row["execution_contract"]["runnable"])
        self.assertFalse(row["execution_contract"]["advisory_only"])
        self.assertEqual(row["gating_test"], row["harness_command"])
        self.assertEqual(row["bindings"]["fixture_source"], "clob_order_lifecycles")
        self.assertTrue(row["bindings"]["generated_test_path"].endswith("Invariant_POLY_CLOB_FILL_01.t.sol"))
        self.assertTrue(row["bindings"]["source_refs"][0].endswith("src/Vault.sol"))
        self.assertEqual(row["missing_inputs"], [])

    def test_current_source_backed_binding_is_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            _write_file(workspace / "poc-tests" / "READY" / "Harness.t.sol", "contract Harness {}\n")
            manifest = MOD.build_manifest(
                [
                    {
                        "row_id": "READY",
                        "title": "Current source backed harness",
                        "binding_scope": "harness",
                        "harness_command": "forge test --match-path poc-tests/READY/Harness.t.sol -vv",
                        "gating_test": "forge test --match-path poc-tests/READY/Harness.t.sol -vv",
                        "source_refs": ["contracts/Vault.sol:1"],
                        "target_entrypoint": "contracts/Vault.sol:1",
                        "actor_setup": "unprivileged attacker",
                        "fixture_source": "fixture:ready",
                        "impact_contract_id": "impact-READY",
                        "generated_test_path": "poc-tests/READY/Harness.t.sol",
                    }
                ],
                workspace=workspace,
            )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["execution_contract"]["claim"], "runnable_harness")
        self.assertTrue(row["execution_contract"]["runnable"])
        self.assertEqual(row["blocked_reasons"], [])
        self.assertTrue(row["source_refs"][0].endswith("contracts/Vault.sol"))

    def test_engage_report_prefixed_source_ref_resolves_to_workspace_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Foo.sol", "contract Foo {}\n")
            _write_file(workspace / "poc-tests" / "READY" / "FooHarness.t.sol", "contract FooHarness {}\n")
            manifest = MOD.build_manifest(
                [
                    {
                        "row_id": "READY",
                        "title": "Engage report source backed harness",
                        "binding_scope": "harness",
                        "harness_command": "forge test --match-path poc-tests/READY/FooHarness.t.sol -vv",
                        "gating_test": "forge test --match-path poc-tests/READY/FooHarness.t.sol -vv",
                        "source_refs": ["engage_report.json:contracts/Foo.sol:87"],
                        "target_entrypoint": "contracts/Foo.sol:87",
                        "actor_setup": "unprivileged attacker",
                        "fixture_source": "fixture:ready",
                        "impact_contract_id": "impact-READY",
                        "generated_test_path": "poc-tests/READY/FooHarness.t.sol",
                    }
                ],
                workspace=workspace,
            )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["execution_contract"]["claim"], "runnable_harness")
        self.assertTrue(row["execution_contract"]["runnable"])
        self.assertEqual(row["blocked_reasons"], [])
        self.assertTrue(row["source_refs"][0].endswith("contracts/Foo.sol"))
        self.assertEqual(row["harness_command"], "forge test --match-path poc-tests/READY/FooHarness.t.sol -vv")

    def test_stale_workspace_binding_is_non_executable_with_typed_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as stale_tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            _write_file(workspace / "poc-tests" / "STALE" / "Harness.t.sol", "contract Harness {}\n")
            manifest = MOD.build_manifest(
                [
                    {
                        "row_id": "STALE",
                        "title": "Stale workspace harness",
                        "binding_scope": "harness",
                        "workspace_path": stale_tmp,
                        "harness_command": "forge test --match-path poc-tests/STALE/Harness.t.sol -vv",
                        "gating_test": "forge test --match-path poc-tests/STALE/Harness.t.sol -vv",
                        "source_refs": ["contracts/Vault.sol:1"],
                        "target_entrypoint": "contracts/Vault.sol:1",
                        "actor_setup": "unprivileged attacker",
                        "fixture_source": "fixture:stale",
                        "impact_contract_id": "impact-STALE",
                        "generated_test_path": "poc-tests/STALE/Harness.t.sol",
                    }
                ],
                workspace=workspace,
            )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "blocked_source_binding")
        self.assertFalse(row["execution_contract"]["runnable"])
        self.assertIn("stale_workspace_binding", row["blockers"])
        self.assertIn("stale_workspace_binding", row["blocked_reasons"])
        self.assertIn("stale_workspace_binding", row["execution_contract"]["blocked_reasons"])

    def test_advisory_only_binding_is_non_executable_with_typed_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            _write_file(workspace / "poc-tests" / "ADVISORY" / "Harness.t.sol", "contract Harness {}\n")
            manifest = MOD.build_manifest(
                [
                    {
                        "row_id": "ADVISORY",
                        "title": "Advisory provenance harness",
                        "binding_scope": "harness",
                        "advisory_only": True,
                        "harness_command": "forge test --match-path poc-tests/ADVISORY/Harness.t.sol -vv",
                        "gating_test": "forge test --match-path poc-tests/ADVISORY/Harness.t.sol -vv",
                        "source_refs": ["contracts/Vault.sol:1"],
                        "target_entrypoint": "contracts/Vault.sol:1",
                        "actor_setup": "unprivileged attacker",
                        "fixture_source": "fixture:advisory",
                        "impact_contract_id": "impact-ADVISORY",
                        "generated_test_path": "poc-tests/ADVISORY/Harness.t.sol",
                    }
                ],
                workspace=workspace,
            )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "blocked_advisory_provenance")
        self.assertFalse(row["execution_contract"]["runnable"])
        self.assertIn("advisory_only_provenance", row["blockers"])
        self.assertIn("advisory_only_provenance", row["blocked_reasons"])

    def test_missing_source_refs_is_non_executable_with_typed_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            _write_file(workspace / "poc-tests" / "NO-SOURCE" / "Harness.t.sol", "contract Harness {}\n")
            manifest = MOD.build_manifest(
                [
                    {
                        "row_id": "NO-SOURCE",
                        "title": "Missing source refs harness",
                        "binding_scope": "harness",
                        "harness_command": "forge test --match-path poc-tests/NO-SOURCE/Harness.t.sol -vv",
                        "gating_test": "forge test --match-path poc-tests/NO-SOURCE/Harness.t.sol -vv",
                        "target_entrypoint": "contracts/Vault.sol:1",
                        "actor_setup": "unprivileged attacker",
                        "fixture_source": "fixture:missing-source",
                        "impact_contract_id": "impact-NO-SOURCE",
                        "generated_test_path": "poc-tests/NO-SOURCE/Harness.t.sol",
                    }
                ],
                workspace=workspace,
            )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "blocked_source_binding")
        self.assertFalse(row["execution_contract"]["runnable"])
        self.assertIn("source_refs", row["missing_inputs"])
        self.assertIn("missing_source_refs", row["blockers"])
        self.assertIn("missing_source_refs", row["blocked_reasons"])

    def test_needs_human_plan_fails_closed_for_vague_fields(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "row_id": "MYSTERY-X-001",
                    "title": "Needs human",
                    "harness_family": "needs_human",
                    "compile_command": "make harness-scaffold WS=<fixture-ws>",
                    "target_entrypoint": "EXPECTED: operator must choose path",
                    "required_fixtures": ["TBD:fixture-kit"],
                    "impact_contract_id": "",
                }
            ]
        )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "blocked_vague_plan")
        self.assertEqual(row["execution_contract"]["claim"], "blocked_harness")
        self.assertFalse(row["execution_contract"]["runnable"])
        self.assertFalse(row["has_executable_harness_command"])
        self.assertIn("harness_command", row["missing_inputs"])
        self.assertIn("target_entrypoint", row["missing_inputs"])
        self.assertIn("fixture_source", row["missing_inputs"])
        self.assertIn("impact_contract_id", row["missing_inputs"])
        self.assertIn("vague_command", row["blockers"])

    def test_report_row_with_prose_gating_test_stays_blocked(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "KLBQ-004",
                    "limitation": "Harness-plan rows still stall at needs_human, missing entrypoint, setup, fixture, and impact-contract bindings.",
                    "concrete_next_patch": "Add a binding-manifest layer for harness plans.",
                    "gating_test": "make harness-scaffold WS=<fixture-ws> must emit either runnable .t.sol plus manifest or a schema-valid blocked binding manifest",
                }
            ]
        )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "blocked_vague_plan")
        self.assertIsNone(row["gating_test"])
        self.assertIn("gating_test", row["missing_inputs"])
        self.assertIn("vague_command", row["blockers"])

    def test_klbq_004_status_refresh_row_can_be_exact_without_harness_inputs(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "KLBQ-004",
                    "limitation": "Harness-plan rows still stall at needs_human, missing entrypoint, setup, fixture, and impact-contract bindings.",
                    "binding_scope": "status_refresh",
                    "harness_command": "python3 -m unittest tools.tests.test_harness_scaffold_emitter -v",
                    "gating_test": "python3 -m unittest tools.tests.test_harness_scaffold_emitter -v",
                }
            ]
        )

        row = manifest["rows"][0]
        self.assertEqual(row["binding_scope"], "status_refresh")
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["execution_contract"]["claim"], "advisory_only")
        self.assertFalse(row["execution_contract"]["runnable"])
        self.assertTrue(row["execution_contract"]["advisory_only"])
        self.assertEqual(row["missing_inputs"], [])
        self.assertEqual(
            row["harness_command"],
            "python3 -m unittest tools.tests.test_harness_scaffold_emitter -v",
        )

    def test_status_refresh_row_with_exact_local_evidence_stays_advisory_only(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "KLBQ-004",
                    "limitation": "Harness-plan rows still stall at needs_human, missing entrypoint, setup, fixture, and impact-contract bindings.",
                    "binding_scope": "status_refresh",
                    "harness_command": "python3 -m unittest tools.tests.test_harness_scaffold_emitter tools.tests.test_harness_binding_manifest tools.tests.test_known_limitations_harness_memory_status -v",
                    "gating_test": "python3 -m unittest tools.tests.test_harness_scaffold_emitter tools.tests.test_harness_binding_manifest tools.tests.test_known_limitations_harness_memory_status -v",
                    "verification_status": "passed",
                    "local_status_packet": "reports/harness_binding_manifest_status_2026-05-05.json",
                    "local_evidence": [
                        "tools/harness-scaffold-emitter.py",
                        "tools/harness-binding-manifest.py",
                        "tools/tests/test_harness_scaffold_emitter.py",
                        "tools/tests/test_harness_binding_manifest.py",
                        "reports/harness_binding_manifest_status_2026-05-05.json",
                    ],
                    "verification_commands": [
                        "python3 -m unittest tools.tests.test_harness_scaffold_emitter tools.tests.test_harness_binding_manifest tools.tests.test_known_limitations_harness_memory_status -v",
                    ],
                    "status_notes": "Harness-scaffold now emits a schema-valid harness_binding_manifest.json beside attempt_manifest.json for ready executable bindings, blocked bindings, and idempotent backfill.",
                }
            ]
        )

        row = manifest["rows"][0]
        self.assertEqual(row["binding_scope"], "status_refresh")
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["execution_contract"]["claim"], "advisory_only")
        self.assertFalse(row["execution_contract"]["runnable"])
        self.assertTrue(row["execution_contract"]["advisory_only"])
        self.assertEqual(row["proof_boundary"], row["execution_contract"]["proof_boundary"])
        self.assertIn("reports/harness_binding_manifest_status_2026-05-05.json", row["expected_artifacts"])
        self.assertTrue(row["execution_contract"]["expected_artifacts"])

    def test_network_and_llm_dispatch_commands_are_blocked(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "R-1",
                    "title": "Bad command",
                    "compile_command": "python3 tools/llm-dispatch.py --prompt-file plan.txt",
                    "gating_test": "curl https://example.com/run-check",
                }
            ]
        )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "blocked_disallowed_command")
        self.assertIn("disallowed_llm_dispatch", row["blockers"])
        self.assertIn("network_access_not_allowed", row["blockers"])
        self.assertFalse(row["has_executable_harness_command"])

    def test_pipe_and_redirection_commands_are_not_executable_bindings(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "PIPE-1",
                    "title": "Piped command",
                    "command": "python3 -m unittest tools.tests.test_harness_execution_queue -v | tee /tmp/gate.log",
                    "gating_test": "python3 -m json.tool reports/harness_execution_queue_2026-05-05.json > /tmp/out.json",
                }
            ]
        )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "blocked_missing_inputs")
        self.assertFalse(row["has_executable_harness_command"])
        self.assertIsNone(row["gating_test"])
        self.assertIn("harness_command", row["missing_inputs"])
        self.assertIn("gating_test", row["missing_inputs"])
        self.assertIn("unsupported_shell_token:|", row["blockers"])
        self.assertIn("unsupported_shell_token:>", row["blockers"])

        assessed = MOD._command_assessment("python3 -c 'print(\"a>b\")'")
        self.assertTrue(assessed["exact"])
        inline_shell = MOD._command_assessment("bash -c 'echo ok | tee /tmp/gate.log'")
        self.assertFalse(inline_shell["exact"])
        self.assertIn("unsupported_shell_inline_command", inline_shell["blockers"])

    def test_load_rows_accepts_jsonl_and_skips_irrelevant_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            path.write_text(
                json.dumps({"id": "A", "note": "ignore me"}) + "\n"
                + json.dumps(
                    {
                        "id": "B",
                        "title": "Scanner rerun",
                        "command": "python3 tools/inventory-smoke-test.py --detector swap-missing-slippage-protection",
                        "gating_test": "python3 -m unittest tools.tests.test_inventory_smoke_test",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            rows = MOD.load_rows(path)
            manifest = MOD.build_manifest(rows)

        self.assertEqual([row["id"] for row in rows], ["A", "B"])
        self.assertEqual(manifest["row_count"], 1)
        row = manifest["rows"][0]
        self.assertEqual(row["row_id"], "B")
        self.assertEqual(row["status"], "ready_executable_binding")

    def test_load_rows_converts_exploit_queue_row_with_existing_proof_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            proof_file = workspace / "poc-tests" / "EQ-READY" / "Exploit.t.sol"
            proof_file.parent.mkdir(parents=True)
            proof_file.write_text("contract Exploit {}\n", encoding="utf-8")
            queue_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-READY",
                                "title": "ready proof",
                                "proof_status": "needs_harness",
                                "proof_path": "foundry",
                                "proof_file": "poc-tests/EQ-READY/Exploit.t.sol",
                                "source_refs": ["contracts/Vault.sol:42"],
                                "target_entrypoint": "contracts/Vault.sol:42",
                                "actor_setup": "unprivileged attacker calls withdraw",
                                "fixture_source": "source_artifact:EQ-READY",
                                "impact_contract_id": "impact-EQ-READY",
                                "next_command": "grep -rn 'withdraw' src/",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)

        self.assertEqual(manifest["row_count"], 1)
        row = manifest["rows"][0]
        self.assertEqual(row["row_id"], "EQ-READY")
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["harness_command"], "forge test --match-path poc-tests/EQ-READY/Exploit.t.sol -vv")
        self.assertEqual(row["gating_test"], row["harness_command"])
        self.assertEqual(row["execution_contract"]["claim"], "runnable_harness")

    def test_typed_admitted_queue_preserves_validated_envelope_in_harness_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            proof_file = workspace / "poc-tests" / "TYPED" / "Exploit.t.sol"
            _write_file(proof_file, "contract Exploit {}\n")
            queue_path = workspace / ".auditooor" / "zero_day_proof_queue_admitted.json"
            queue_path.parent.mkdir(parents=True)
            parent = ["zdo_parent", "zdr_revision"]
            queue_path.write_text(json.dumps({
                "schema": "auditooor.exploit_queue.v1",
                "queue": [{
                    "lead_id": "zdpq_typed",
                    "title": "typed proof",
                    "obligation_id": parent[0],
                    "revision_id": parent[1],
                    "proof_path": "foundry",
                    "proof_file": "poc-tests/TYPED/Exploit.t.sol",
                    "source_refs": ["contracts/Vault.sol:42"],
                    "target_entrypoint": "contracts/Vault.sol:42",
                    "actor_setup": "unprivileged attacker",
                    "fixture_source": "source_artifact:typed",
                    "impact_contract_id": "impact-TYPED",
                    "zero_day_proof_projection": {
                        "schema": "auditooor.zero_day_proof_queue_projection.v1",
                        "freeze_receipt_id": "a" * 64,
                        "freeze_input_fingerprint": "b" * 64,
                        "obligation_source_row_sha256": "c" * 64,
                        "parent_ids": parent,
                        "selection_ordinal": 1,
                        "question_evidence": [{"question_id": "q0", "axis": "asset_invariant"}],
                    },
                    "zero_day_proof_admission": {
                        "freeze_receipt_id": "a" * 64,
                        "input_fingerprint": "b" * 64,
                        "obligation_source_row_sha256": "c" * 64,
                        "parent_ids": parent,
                    },
                }],
                "entries": [],
                "zero_day_proof_admission": {
                    "schema": "auditooor.zero_day_proof_admission.v1",
                    "admission_id": "zdpa_" + "d" * 64,
                    "freeze_receipt_id": "a" * 64,
                    "freeze_input_fingerprint": "b" * 64,
                    "input_queue_sha256": "e" * 64,
                    "admitted_count": 1,
                    "admitted_parents": [{"obligation_id": parent[0], "revision_id": parent[1]}],
                },
            }), encoding="utf-8")

            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)

        self.assertEqual(1, manifest["typed_proof_envelope_entry_count"])
        self.assertEqual("auditooor.zero_day_proof_envelope.v1", manifest["typed_proof_envelope_schema"])
        envelope = manifest["rows"][0]["zero_day_proof_envelope"]
        self.assertEqual(["zdo_parent", "zdr_revision"], envelope["parent_ids"])
        self.assertEqual("zdpq_typed", envelope["lead_id"])
        self.assertTrue(envelope["envelope_id"].startswith("zdpe_"))

    def test_typed_admitted_queue_rejects_legacy_entries_bucket(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            queue_path = workspace / ".auditooor" / "zero_day_proof_queue_admitted.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(json.dumps({
                "schema": "auditooor.exploit_queue.v1",
                "queue": [],
                "entries": [{"lead_id": "legacy"}],
                "zero_day_proof_admission": {
                    "schema": "auditooor.zero_day_proof_admission.v1",
                    "admission_id": "zdpa_" + "d" * 64,
                    "freeze_receipt_id": "a" * 64,
                    "freeze_input_fingerprint": "b" * 64,
                    "input_queue_sha256": "e" * 64,
                    "admitted_count": 0,
                    "admitted_parents": [],
                },
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "typed_proof_envelope_legacy_entries_present"):
                MOD.load_rows(queue_path)

    def test_load_rows_reads_exploit_queue_entries_when_queue_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            proof_file = workspace / "poc-tests" / "EQ-ENTRY" / "Exploit.t.sol"
            proof_file.parent.mkdir(parents=True)
            proof_file.write_text("contract Exploit {}\n", encoding="utf-8")
            queue_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [],
                        "entries": [
                            {
                                "lead_id": "EQ-ENTRY",
                                "title": "entry proof",
                                "proof_status": "needs_harness",
                                "proof_path": "foundry",
                                "proof_file": "poc-tests/EQ-ENTRY/Exploit.t.sol",
                                "source_refs": ["contracts/Vault.sol:42"],
                                "target_entrypoint": "contracts/Vault.sol:42",
                                "actor_setup": "unprivileged attacker calls withdraw",
                                "fixture_source": "source_artifact:EQ-ENTRY",
                                "impact_contract_id": "impact-EQ-ENTRY",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)

        self.assertEqual(manifest["row_count"], 1)
        row = manifest["rows"][0]
        self.assertEqual(row["row_id"], "EQ-ENTRY")
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["harness_command"], "forge test --match-path poc-tests/EQ-ENTRY/Exploit.t.sol -vv")

    def test_exploit_queue_next_command_is_not_misused_as_harness_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            queue_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-SOURCE-ONLY",
                                "title": "source only",
                                "proof_status": "needs_harness",
                                "proof_path": "foundry",
                                "source_refs": ["contracts/Vault.sol:42"],
                                "source_artifact_path": ".auditooor/source_artifacts/EQ-SOURCE-ONLY.source_artifact.json",
                                "next_command": "grep -rn 'withdraw' src/",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)

        row = manifest["rows"][0]
        self.assertEqual(row["row_id"], "EQ-SOURCE-ONLY")
        # A foundry-kind row with a valid in-scope source_ref but no proof_file now
        # MATERIALIZES a skeleton (binding_status=materialized-skeleton). The core
        # protection of this test still holds: the grep next_command is NOT misused as
        # the harness_command - the command is the materialized forge invocation.
        self.assertEqual(row["binding_status"], "materialized-skeleton")
        self.assertIsNotNone(row["harness_command"])
        self.assertIn("forge test --match-path", row["harness_command"])
        self.assertNotIn("grep", row["harness_command"])
        # Still not a runnable proof: a TODO-body skeleton lacks the other harness inputs.
        self.assertNotEqual(row["status"], "ready_executable_binding")
        self.assertNotEqual(row["execution_contract"]["claim"], "runnable_harness")
        self.assertEqual(row["bindings"]["target_entrypoint"], "contracts/Vault.sol:42")

    def test_exploit_queue_explicit_harness_command_survives_conversion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            harness = workspace / "poc-tests" / "EQ-EXPLICIT" / "run_harness.sh"
            source_artifact = workspace / ".auditooor" / "source_artifacts" / "EQ-EXPLICIT.source_artifact.json"
            queue_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
            harness.parent.mkdir(parents=True)
            source_artifact.parent.mkdir(parents=True)
            queue_path.parent.mkdir(parents=True, exist_ok=True)
            harness.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            source_artifact.write_text('{"source":"fixture"}\n', encoding="utf-8")
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-EXPLICIT",
                                "title": "explicit runnable proof",
                                "proof_status": "needs_harness",
                                "proof_path": "manual",
                                "generated_test_path": "poc-tests/EQ-EXPLICIT/run_harness.sh",
                                "harness_command": "bash poc-tests/EQ-EXPLICIT/run_harness.sh",
                                "gating_test": "bash poc-tests/EQ-EXPLICIT/run_harness.sh",
                                "source_refs": ["contracts/Vault.sol:42"],
                                "target_entrypoint": "contracts/Vault.sol:42",
                                "actor_setup": "unprivileged attacker triggers withdrawal",
                                "fixture_source": ".auditooor/source_artifacts/EQ-EXPLICIT.source_artifact.json",
                                "source_artifact_path": ".auditooor/source_artifacts/EQ-EXPLICIT.source_artifact.json",
                                "impact_contract_id": "impact-EQ-EXPLICIT",
                                "next_command": "grep -rn 'withdraw' src/",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)

        row = manifest["rows"][0]
        self.assertEqual(row["row_id"], "EQ-EXPLICIT")
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["harness_command"], "bash poc-tests/EQ-EXPLICIT/run_harness.sh")
        self.assertEqual(row["gating_test"], "bash poc-tests/EQ-EXPLICIT/run_harness.sh")
        self.assertEqual(row["bindings"]["impact_contract_id"], "impact-EQ-EXPLICIT")
        self.assertEqual(row["execution_contract"]["claim"], "runnable_harness")
        self.assertNotIn("grep -rn", row["harness_command"])

    def test_exploit_queue_missing_proof_file_does_not_emit_harness_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            queue_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-MISSING",
                                "title": "missing proof file",
                                "proof_status": "needs_harness",
                                "proof_path": "foundry",
                                "proof_file": "poc-tests/EQ-MISSING/Exploit.t.sol",
                                "source_refs": ["contracts/Vault.sol:42"],
                                "target_entrypoint": "contracts/Vault.sol:42",
                                "actor_setup": "unprivileged attacker",
                                "fixture_source": "source_artifact:EQ-MISSING",
                                "impact_contract_id": "impact-EQ-MISSING",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)

        row = manifest["rows"][0]
        self.assertEqual(row["row_id"], "EQ-MISSING")
        self.assertEqual(row["status"], "blocked_missing_inputs")
        self.assertIsNone(row["harness_command"])
        self.assertIn("harness_command", row["missing_inputs"])

    def test_exploit_queue_explicit_command_without_local_proof_file_stays_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            queue_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-NO-PROOF",
                                "title": "explicit command without proof",
                                "proof_status": "needs_harness",
                                "proof_path": "manual",
                                "proof_file": "poc-tests/EQ-NO-PROOF/run_harness.sh",
                                "harness_command": "bash poc-tests/EQ-NO-PROOF/run_harness.sh",
                                "gating_test": "bash poc-tests/EQ-NO-PROOF/run_harness.sh",
                                "source_refs": ["contracts/Vault.sol:42"],
                                "target_entrypoint": "contracts/Vault.sol:42",
                                "actor_setup": "unprivileged attacker",
                                "fixture_source": "source_artifact:EQ-NO-PROOF",
                                "impact_contract_id": "impact-EQ-NO-PROOF",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)

        row = manifest["rows"][0]
        self.assertEqual(row["row_id"], "EQ-NO-PROOF")
        self.assertEqual(row["status"], "blocked_missing_inputs")
        self.assertIsNone(row["harness_command"])
        self.assertIsNone(row["gating_test"])
        self.assertIn("harness_command", row["missing_inputs"])
        self.assertIn("gating_test", row["missing_inputs"])

    def test_exploit_queue_proof_file_outside_workspace_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            outside = Path(tmp).parent / "outside_proof.t.sol"
            outside.write_text("contract Outside {}\n", encoding="utf-8")
            self.addCleanup(lambda: outside.unlink(missing_ok=True))
            queue_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-OUTSIDE",
                                "title": "outside proof file",
                                "proof_status": "needs_harness",
                                "proof_path": "foundry",
                                "proof_file": str(outside),
                                "source_refs": ["contracts/Vault.sol:42"],
                                "target_entrypoint": "contracts/Vault.sol:42",
                                "actor_setup": "unprivileged attacker",
                                "fixture_source": "source_artifact:EQ-OUTSIDE",
                                "impact_contract_id": "impact-EQ-OUTSIDE",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "blocked_missing_inputs")
        self.assertIsNone(row["harness_command"])

    def test_composed_chain_harness_blocks_without_producer_state_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            harness = workspace / "poc-tests" / "CHAIN-001" / "test_chain.py"
            source = workspace / "src" / "Router.sol"
            harness.parent.mkdir(parents=True)
            harness.write_text("print('chain harness')\n", encoding="utf-8")
            source.parent.mkdir(parents=True)
            source.write_text("contract Router {}\n", encoding="utf-8")

            manifest = MOD.build_manifest(
                [
                    {
                        "row_id": "CHAIN-001",
                        "binding_scope": "composed_chain_harness",
                        "chain_id": "CHAIN-001",
                        "producer_lead_id": "EQ-PRODUCER",
                        "consumer_lead_id": "EQ-CONSUMER",
                        "bridging_state": "vault_locked_balance",
                        "source_refs": ["src/Router.sol:44"],
                        "consumer_entrypoint": "src/Router.sol:44",
                        "generated_test_path": "poc-tests/CHAIN-001/test_chain.py",
                        "harness_command": "python3 poc-tests/CHAIN-001/test_chain.py",
                        "gating_test": "python3 poc-tests/CHAIN-001/test_chain.py",
                    }
                ],
                workspace=workspace,
            )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "blocked_missing_inputs")
        self.assertEqual(row["execution_contract"]["claim"], "blocked_harness")
        self.assertIn("producer_state_artifact", row["missing_inputs"])
        self.assertIn("fixture_source", row["missing_inputs"])

    def test_composed_chain_harness_ready_with_harness_file_and_producer_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            harness = workspace / "poc-tests" / "CHAIN-001" / "test_chain.py"
            fixture = workspace / "fixtures" / "producer_state.json"
            source = workspace / "src" / "Router.sol"
            harness.parent.mkdir(parents=True)
            fixture.parent.mkdir(parents=True)
            source.parent.mkdir(parents=True)
            harness.write_text("print('chain harness')\n", encoding="utf-8")
            fixture.write_text('{"locked_balance": 7}\n', encoding="utf-8")
            source.write_text("contract Router {}\n", encoding="utf-8")

            manifest = MOD.build_manifest(
                [
                    {
                        "row_id": "CHAIN-001",
                        "binding_scope": "composed_chain_harness",
                        "chain_id": "CHAIN-001",
                        "producer_lead_id": "EQ-PRODUCER",
                        "consumer_lead_id": "EQ-CONSUMER",
                        "bridging_state": "vault_locked_balance",
                        "producer_state_artifact": "fixtures/producer_state.json",
                        "source_refs": ["src/Router.sol:44"],
                        "consumer_entrypoint": "src/Router.sol:44",
                        "generated_test_path": "poc-tests/CHAIN-001/test_chain.py",
                        "harness_command": "python3 poc-tests/CHAIN-001/test_chain.py",
                        "gating_test": "python3 poc-tests/CHAIN-001/test_chain.py",
                    }
                ],
                workspace=workspace,
            )

        row = manifest["rows"][0]
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["execution_contract"]["claim"], "runnable_harness")
        self.assertEqual(row["execution_contract"]["required_for_runnable"], list(MOD.RUNNABLE_COMPOSED_CHAIN_REQUIRED_INPUTS))
        self.assertEqual(row["bindings"]["producer_state_artifact"], "fixtures/producer_state.json")
        self.assertTrue(row["bindings"]["fixture_source"].endswith("fixtures/producer_state.json"))
        self.assertTrue(row["bindings"]["generated_test_path"].endswith("poc-tests/CHAIN-001/test_chain.py"))
        self.assertEqual(row["chain_id"], "CHAIN-001")
        self.assertEqual(row["bridging_state"], "vault_locked_balance")


    def test_exploit_queue_no_proof_file_materializes_forge_skeleton(self) -> None:
        # Real exploit-queue rows carry proof_path (a KIND) + source_refs but NO proof_file.
        # Before the fix every such row was blocked_harness (ready_count=0). After the fix
        # they materialize a runnable-but-TODO skeleton; binding_status is materialized-skeleton
        # (NOT proven), the generated_test_path is a real on-disk file, command is non-None.
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            converted = MOD._exploit_queue_row_to_harness_row(
                {
                    "lead_id": "EQ-MAT-FORGE",
                    "title": "no proof file, foundry kind",
                    "proof_status": "needs_harness",
                    "proof_path": "foundry",
                    "harness_family": "forge_invariant",
                    "source_refs": ["contracts/Vault.sol:42"],
                    "next_command": "grep -rn withdraw contracts/",
                },
                workspace,
            )

            self.assertEqual(converted["binding_status"], "materialized-skeleton")
            generated = converted["generated_test_path"]
            self.assertIsNotNone(generated)
            self.assertTrue(Path(generated).is_file(), generated)
            self.assertIn("poc-tests", generated)
            self.assertIn("-engine-harness", generated)
            self.assertTrue(generated.endswith(".t.sol"))
            self.assertIsNotNone(converted.get("harness_command"))
            self.assertIn("forge test --match-path", converted["harness_command"])
            # Honesty: the skeleton body is a failing TODO, never a claimed pass.
            body = Path(generated).read_text(encoding="utf-8")
            self.assertIn("MATERIALIZED SKELETON", body)
            self.assertIn("TODO", body)
            self.assertIn("contracts/Vault.sol:42", body)

    def test_exploit_queue_no_proof_file_materializes_cargo_skeleton(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "src" / "lib.rs", "pub fn f() {}\n")
            converted = MOD._exploit_queue_row_to_harness_row(
                {
                    "lead_id": "EQ-MAT-CARGO",
                    "title": "no proof file, rust kind",
                    "proof_status": "needs_harness",
                    "proof_path": "solana-program-test",
                    "harness_family": "cargo_unit_test",
                    "source_refs": ["src/lib.rs:10"],
                },
                workspace,
            )

            self.assertEqual(converted["binding_status"], "materialized-skeleton")
            generated = converted["generated_test_path"]
            self.assertIsNotNone(generated)
            self.assertTrue(Path(generated).is_file(), generated)
            self.assertTrue(generated.endswith("_smoke.rs"))
            self.assertEqual(converted["harness_command"], "cargo test")
            body = Path(generated).read_text(encoding="utf-8")
            self.assertIn("MATERIALIZED SKELETON", body)
            self.assertIn("src/lib.rs:10", body)

    def test_exploit_queue_no_proof_file_no_source_ref_stays_blocked(self) -> None:
        # No in-scope source_ref => nothing to bind against => no materialization.
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            converted = MOD._exploit_queue_row_to_harness_row(
                {
                    "lead_id": "EQ-NO-REF",
                    "title": "no proof file, no resolvable ref",
                    "proof_path": "foundry",
                    "harness_family": "forge_invariant",
                    "source_refs": ["contracts/DoesNotExist.sol:1"],
                },
                workspace,
            )
            self.assertNotIn("binding_status", converted)
            self.assertIsNone(converted["generated_test_path"])
            self.assertNotIn("harness_command", converted)

    def test_declared_but_missing_proof_file_is_not_materialized(self) -> None:
        # A row that NAMES a specific proof_file that does not exist must stay blocked -
        # we do not fabricate the author's named path. (Regression guard vs the existing
        # test_exploit_queue_missing_proof_file_does_not_emit_harness_command contract.)
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            queue_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-DECLARED-MISSING",
                                "title": "declared missing proof file",
                                "proof_path": "foundry",
                                "proof_file": "poc-tests/EQ-DECLARED-MISSING/Exploit.t.sol",
                                "source_refs": ["contracts/Vault.sol:42"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)

        row = manifest["rows"][0]
        self.assertIsNone(row.get("binding_status"))
        self.assertIsNone(row["harness_command"])
        self.assertNotEqual(row["status"], "ready_executable_binding")

    def test_materialized_skeleton_survives_into_manifest_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_file(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
            queue_path = workspace / ".auditooor" / "exploit_queue.source_mined.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-MAT-MANIFEST",
                                "title": "materialized into manifest",
                                "proof_path": "foundry",
                                "harness_family": "forge_invariant",
                                "source_refs": ["contracts/Vault.sol:42"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            rows = MOD.load_rows(queue_path)
            manifest = MOD.build_manifest(rows, workspace=workspace, source_path=queue_path)
            row = manifest["rows"][0]
            self.assertEqual(row["binding_status"], "materialized-skeleton")
            self.assertIsNotNone(row["bindings"]["generated_test_path"])
            # File must exist while the workspace lives (assert inside the tempdir scope).
            self.assertTrue(Path(row["bindings"]["generated_test_path"]).is_file())

        self.assertIsNotNone(row["harness_command"])
        # Honesty: a TODO-body skeleton is NOT a runnable proof; the execution contract
        # must not claim runnable_harness off a skeleton alone.
        self.assertNotEqual(row["execution_contract"]["claim"], "runnable_harness")


if __name__ == "__main__":
    unittest.main()
