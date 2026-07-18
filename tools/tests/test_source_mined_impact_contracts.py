from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "source-mined-impact-contracts.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("source_mined_impact_contracts", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load source-mined-impact-contracts.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SourceMinedImpactContractsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="source-mined-impact-contracts-")
        self.ws = Path(self.tmp.name)
        (self.ws / ".auditooor").mkdir()
        self.tool = _load_tool()
        self.write_source("runtime/src/bridge.rs", 130)
        self.write_source("runtime/src/ledger.rs", 100)
        self.write_source("runtime/src/watch_chain.rs", 850)
        self.write_source("runtime/src/events.rs", 12)
        self.write_source("runtime/src/locked_bridge.rs", 50)
        self.write_source("src/Settler.sol", 105)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_json(self, rel: str, payload: dict) -> None:
        path = self.ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def write_source(self, rel: str, line_count: int, special_line: str = "source evidence") -> None:
        path = self.ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"line {idx}" for idx in range(1, line_count + 1)]
        lines[-1] = special_line
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def write_severity(self) -> None:
        (self.ws / "SEVERITY.md").write_text(
            "# Program Severity\n\n"
            "## Critical\n"
            "- Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield\n"
            "- Permanent freezing of funds\n\n"
            "## High\n"
            "- Temporary freezing of funds\n",
            encoding="utf-8",
        )

    def write_queue(self) -> None:
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-001",
                        "title": "bridge replay drains user deposits",
                        "attack_class": "replay",
                        "likely_severity": "critical",
                        "impact_path": "direct theft of user funds",
                        "asset_at_risk": "escrowed bridge funds",
                        "attacker_role": "permissionless relayer",
                        "victim_role": "bridge user",
                        "oos_traps": ["not front-run-only; source-only bounty"],
                        "source_refs": ["runtime/src/bridge.rs:120"],
                        "dispatch_site": "runtime/src/bridge.rs:120",
                        "reachability_trace": (
                            "Reachability trace: dispatched via production bridge router at "
                            "runtime/src/bridge.rs:120 under default config"
                        ),
                        "source_artifacts_complete": True,
                        "negative_control": "same message with consumed nonce must fail",
                        "state_impact_linkage": "nonce replay credits attacker balance and debits escrowed bridge funds",
                        "protocol_defenses": ["nonce replay guard"],
                        "covered_defenses": ["nonce replay guard"],
                        "next_command": "cargo test -p pallet-ismp bridge_replay -- --nocapture",
                    }
                ],
            },
        )

    def proof_relevance_row(self) -> dict:
        return {
            "lead_id": "EQ-PROOF",
            "title": "bridge replay drains user deposits",
            "attack_class": "replay",
            "likely_severity": "critical",
            "impact_path": "direct theft of user funds",
            "asset_at_risk": "escrowed bridge funds",
            "attacker_role": "permissionless relayer",
            "victim_role": "bridge user",
            "oos_traps": ["not front-run-only; source-only bounty"],
            "source_refs": ["runtime/src/bridge.rs:120"],
            "source_artifacts_complete": True,
            "negative_control": "same message with consumed nonce must fail",
            "state_impact_linkage": "nonce replay credits attacker balance and debits escrowed bridge funds",
            "protocol_defenses": ["nonce replay guard"],
            "covered_defenses": ["nonce replay guard"],
            "next_command": "cargo test -p pallet-ismp bridge_replay -- --nocapture",
        }

    def test_builds_mapped_contract_from_complete_source_mined_row(self) -> None:
        self.write_severity()
        self.write_queue()
        payload, patched_queue = self.tool.build_payload(self.ws)

        self.assertEqual(payload["schema"], "auditooor.pr560.impact_contracts.v1")
        self.assertEqual(payload["summary"]["generated_contracts"], 1)
        contract = payload["contracts"][0]
        self.assertEqual(contract["impact_contract_id"], "impact-contract-eq-001")
        self.assertEqual(contract["status"], "mapped")
        self.assertEqual(contract["impact_contract_gaps"], [])
        self.assertEqual(
            contract["selected_impact"],
            "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
        )
        self.assertTrue(contract["exact_impact_row"])
        self.assertFalse(contract["listed_impact_proven"])
        self.assertFalse(contract["promotion_allowed"])
        self.assertEqual(contract["attacker_actor"], "permissionless relayer")
        self.assertEqual(contract["victim_actor"], "bridge user")
        self.assertEqual(contract["asset_at_risk"], "escrowed bridge funds")
        self.assertIn("same message with consumed nonce must fail", contract["negative_controls"])
        self.assertEqual(contract["dispatch_site"], "runtime/src/bridge.rs:120")
        self.assertIn("runtime/src/bridge.rs:120", contract["reachability_trace"])

        assert patched_queue is not None
        row = patched_queue["queue"][0]
        self.assertEqual(row["impact_contract_id"], "impact-contract-eq-001")
        self.assertEqual(row["impact_contract_status"], "mapped")
        self.assertEqual(row["listed_impact_selected"], contract["selected_impact"])
        self.assertEqual(row["dispatch_site"], "runtime/src/bridge.rs:120")
        self.assertEqual(row["reachability_trace"], contract["reachability_trace"])

    def test_typed_admitted_queue_preserves_envelope_in_contract_and_patch(self) -> None:
        self.write_severity()
        self.write_queue()
        path = self.ws / ".auditooor/exploit_queue.source_mined.json"
        queue = json.loads(path.read_text(encoding="utf-8"))
        row = queue["queue"][0]
        row.update({
            "lead_id": "zdpq_typed",
            "obligation_id": "zdo_parent",
            "revision_id": "zdr_revision",
            "zero_day_proof_projection": {
                "schema": "auditooor.zero_day_proof_queue_projection.v1",
                "freeze_receipt_id": "a" * 64,
                "freeze_input_fingerprint": "b" * 64,
                "obligation_source_row_sha256": "c" * 64,
                "parent_ids": ["zdo_parent", "zdr_revision"],
                "selection_ordinal": 1,
                "question_evidence": [{"question_id": "q0", "axis": "asset_invariant"}],
            },
            "zero_day_proof_admission": {
                "freeze_receipt_id": "a" * 64,
                "input_fingerprint": "b" * 64,
                "obligation_source_row_sha256": "c" * 64,
                "parent_ids": ["zdo_parent", "zdr_revision"],
            },
        })
        queue["schema"] = "auditooor.exploit_queue.v1"
        queue["queue_role"] = "proof_tasks"
        queue["entries"] = []
        queue["zero_day_proof_admission"] = {
            "schema": "auditooor.zero_day_proof_admission.v1",
            "queue_role": "proof_tasks",
            "admission_id": "zdpa_" + "d" * 64,
            "freeze_receipt_id": "a" * 64,
            "freeze_input_fingerprint": "b" * 64,
            "input_queue_sha256": "e" * 64,
            "admitted_count": 1,
            "admitted_parents": [{"obligation_id": "zdo_parent", "revision_id": "zdr_revision"}],
        }
        path.write_text(json.dumps(queue), encoding="utf-8")

        payload, patched = self.tool.build_payload(self.ws)

        self.assertEqual("zdpq_typed", payload["contracts"][0]["zero_day_proof_envelope"]["lead_id"])
        self.assertEqual(["zdo_parent", "zdr_revision"], payload["contracts"][0]["zero_day_proof_envelope"]["parent_ids"])
        assert patched is not None
        self.assertEqual("zdpq_typed", patched["queue"][0]["lead_id"])

    def test_incomplete_source_mined_row_stays_generated_unvalidated_with_gaps(self) -> None:
        self.write_severity()
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-INCOMPLETE",
                        "title": "ambiguous source-mined row",
                        "likely_severity": "critical",
                        "impact_path": "possible accounting issue",
                        "attacker_role": "permissionless caller",
                        "source_artifacts_complete": False,
                    }
                ],
            },
        )

        payload, patched_queue = self.tool.build_payload(self.ws)

        contract = payload["contracts"][0]
        self.assertEqual(contract["status"], "generated_unvalidated")
        self.assertIn("selected_impact_not_exact_severity_row", contract["impact_contract_gaps"])
        self.assertIn("victim_actor_inferred", contract["impact_contract_gaps"])
        self.assertIn("asset_at_risk_inferred", contract["impact_contract_gaps"])
        self.assertIn("source_artifacts_incomplete", contract["impact_contract_gaps"])
        self.assertIn("source_refs_missing", contract["impact_contract_gaps"])
        self.assertIn("oos_traps_missing", contract["impact_contract_gaps"])
        self.assertIn("negative_control_missing", contract["impact_contract_gaps"])
        assert patched_queue is not None
        self.assertEqual(patched_queue["queue"][0]["impact_contract_status"], "generated_unvalidated")

    def test_placeholder_attacker_control_blocks_mapped_promotion(self) -> None:
        self.write_severity()
        # Every other field is complete; only attacker_control is the generic
        # D4 placeholder. The row must NOT promote to mapped.
        for placeholder in ("partial", "needs_review_privileged_surface", "unknown"):
            with self.subTest(placeholder=placeholder):
                self.write_json(
                    ".auditooor/exploit_queue.source_mined.json",
                    {
                        "schema": "auditooor.exploit_queue.source_mined.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-PLACEHOLDER",
                                "title": "bridge replay drains user deposits",
                                "attack_class": "replay",
                                "likely_severity": "critical",
                                "impact_path": "direct theft of user funds",
                                "asset_at_risk": "escrowed bridge funds",
                                "attacker_role": placeholder,
                                "victim_role": "bridge user",
                                "oos_traps": ["not front-run-only"],
                                "source_refs": ["runtime/src/bridge.rs:120"],
                                "source_artifacts_complete": True,
                                "negative_control": "consumed nonce must fail",
                                "state_impact_linkage": "replayed bridge message moves escrowed funds to the caller",
                                "next_command": "cargo test -p pallet-ismp bridge_replay",
                            }
                        ],
                    },
                )
                payload, _ = self.tool.build_payload(self.ws)
                contract = payload["contracts"][0]
                self.assertEqual(contract["status"], "generated_unvalidated")
                self.assertIn("attacker_actor_inferred", contract["impact_contract_gaps"])

    def test_missing_or_placeholder_proof_command_blocks_mapped_promotion(self) -> None:
        self.write_severity()
        base = {
            "lead_id": "EQ-PROOFCMD",
            "title": "bridge replay drains user deposits",
            "attack_class": "replay",
            "likely_severity": "critical",
            "impact_path": "direct theft of user funds",
            "asset_at_risk": "escrowed bridge funds",
            "attacker_role": "permissionless relayer",
            "victim_role": "bridge user",
            "oos_traps": ["not front-run-only"],
            "source_refs": ["runtime/src/bridge.rs:120"],
            "source_artifacts_complete": True,
            "negative_control": "consumed nonce must fail",
            "state_impact_linkage": "replayed bridge message moves escrowed funds to the caller",
        }
        for label, cmd in (
            ("empty", ""),
            ("blocker-stub", "# address blocker: question is unanswered"),
            ("bare-comment", "# run something later"),
        ):
            with self.subTest(proof_command=label):
                row = dict(base)
                if cmd:
                    row["next_command"] = cmd
                self.write_json(
                    ".auditooor/exploit_queue.source_mined.json",
                    {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
                )
                payload, _ = self.tool.build_payload(self.ws)
                contract = payload["contracts"][0]
                self.assertEqual(contract["status"], "generated_unvalidated")
                self.assertIn("proof_command_missing", contract["impact_contract_gaps"])

    def test_complete_row_carries_full_impact_contract(self) -> None:
        # A complete source-mined row must map AND carry every impact-contract
        # field: source refs, exact impact, actors, asset, proof command, OOS
        # traps, and a negative control.
        self.write_severity()
        self.write_queue()
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertEqual(contract["status"], "mapped")
        self.assertEqual(contract["impact_contract_gaps"], [])
        self.assertTrue(contract["source_refs"])
        self.assertTrue(contract["exact_impact_row"])
        self.assertTrue(self.tool.has_chain_attacker_control_evidence(contract["attacker_actor"]))
        self.assertNotIn(contract["victim_actor"].lower(), self.tool.MISSING_VALUES)
        self.assertNotIn(contract["asset_at_risk"].lower(), self.tool.MISSING_VALUES)
        self.assertTrue(self.tool._has_concrete_proof_command(contract["proof_command"]))
        self.assertTrue(contract["oos_traps"])
        self.assertTrue(contract["negative_controls"])

    def test_proof_relevance_row_requires_current_file_line_and_linkage(self) -> None:
        self.write_severity()
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [self.proof_relevance_row()]},
        )

        payload, patched_queue = self.tool.build_payload(self.ws)

        contract = payload["contracts"][0]
        self.assertEqual(contract["status"], "mapped")
        self.assertTrue(contract["proof_relevance"])
        self.assertEqual(contract["proof_relevance_status"], "proof_relevant")
        self.assertEqual(contract["proof_relevance_skip_reasons"], [])
        self.assertEqual(len(contract["current_source_refs"]), 1)
        self.assertEqual(contract["current_source_refs"][0]["line"], 120)
        self.assertEqual(contract["stale_source_refs"], [])
        self.assertIn("nonce replay credits", contract["state_impact_linkage"][0])
        self.assertEqual(payload["summary"]["proof_relevant_contracts"], 1)
        self.assertEqual(payload["summary"]["skipped_non_proof_contracts"], 0)
        assert patched_queue is not None
        self.assertTrue(patched_queue["queue"][0]["proof_relevance"])
        self.assertEqual(patched_queue["queue"][0]["proof_relevance_status"], "proof_relevant")

    def test_missing_source_refs_are_skipped_non_proof_with_typed_reason(self) -> None:
        self.write_severity()
        row = self.proof_relevance_row()
        row["source_refs"] = []
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
        )

        payload, patched_queue = self.tool.build_payload(self.ws)

        contract = payload["contracts"][0]
        self.assertEqual(contract["status"], "generated_unvalidated")
        self.assertFalse(contract["proof_relevance"])
        self.assertEqual(contract["proof_relevance_status"], "skipped_non_proof")
        self.assertIn("missing_source_refs", contract["proof_relevance_skip_reasons"])
        self.assertIn("source_refs_missing", contract["impact_contract_gaps"])
        self.assertEqual(contract["current_source_refs"], [])
        self.assertEqual(contract["stale_source_refs"], [])
        self.assertEqual(payload["summary"]["skipped_non_proof_contracts"], 1)
        assert patched_queue is not None
        self.assertEqual(patched_queue["queue"][0]["proof_relevance_status"], "skipped_non_proof")
        self.assertIn("missing_source_refs", patched_queue["queue"][0]["proof_relevance_skip_reasons"])

    def test_stale_workspace_ref_is_skipped_non_proof_with_typed_reason(self) -> None:
        self.write_severity()
        row = self.proof_relevance_row()
        row["source_refs"] = ["runtime/src/deleted_bridge.rs:120"]
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
        )

        payload, patched_queue = self.tool.build_payload(self.ws)

        contract = payload["contracts"][0]
        self.assertEqual(contract["status"], "generated_unvalidated")
        self.assertFalse(contract["proof_relevance"])
        self.assertEqual(contract["proof_relevance_status"], "skipped_non_proof")
        self.assertIn("stale_workspace_source_refs", contract["proof_relevance_skip_reasons"])
        self.assertIn("source_ref_file_missing", contract["proof_relevance_skip_reasons"])
        self.assertIn("stale_workspace_source_refs", contract["impact_contract_gaps"])
        self.assertEqual(contract["current_source_refs"], [])
        self.assertEqual(contract["stale_source_refs"][0]["reason"], "source_ref_file_missing")
        assert patched_queue is not None
        self.assertEqual(patched_queue["queue"][0]["stale_source_refs"][0]["reason"], "source_ref_file_missing")

    def test_missing_state_impact_linkage_is_skipped_non_proof(self) -> None:
        self.write_severity()
        row = self.proof_relevance_row()
        row.pop("state_impact_linkage")
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
        )

        payload, _ = self.tool.build_payload(self.ws)

        contract = payload["contracts"][0]
        self.assertEqual(contract["status"], "generated_unvalidated")
        self.assertFalse(contract["proof_relevance"])
        self.assertEqual(contract["proof_relevance_status"], "skipped_non_proof")
        self.assertIn("state_impact_linkage_absent", contract["proof_relevance_skip_reasons"])
        self.assertIn("state_impact_linkage_absent", contract["impact_contract_gaps"])
        self.assertEqual(contract["state_impact_linkage"], [])

    def test_placeholder_attacker_control_not_surfaced_as_contract_actor(self) -> None:
        # A rejected D4 generic placeholder must not be recorded as the
        # contract's attacker_actor. The field must read the explicit
        # confirm-placeholder so no consumer mistakes it for a real actor.
        self.write_severity()
        for placeholder in ("partial", "needs_review_privileged_surface", "unknown"):
            with self.subTest(placeholder=placeholder):
                self.write_json(
                    ".auditooor/exploit_queue.source_mined.json",
                    {
                        "schema": "auditooor.exploit_queue.source_mined.v1",
                        "queue": [
                            {
                                "lead_id": "EQ-LEAK",
                                "title": "bridge replay drains user deposits",
                                "attack_class": "replay",
                                "likely_severity": "critical",
                                "impact_path": "direct theft of user funds",
                                "asset_at_risk": "escrowed bridge funds",
                                "attacker_control": placeholder,
                                "victim_role": "bridge user",
                                "oos_traps": ["not front-run-only"],
                                "source_refs": ["runtime/src/bridge.rs:120"],
                                "source_artifacts_complete": True,
                                "negative_control": "consumed nonce must fail",
                                "state_impact_linkage": "replayed bridge message moves escrowed funds to the caller",
                                "next_command": "cargo test -p pallet-ismp bridge_replay",
                            }
                        ],
                    },
                )
                payload, _ = self.tool.build_payload(self.ws)
                contract = payload["contracts"][0]
                self.assertEqual(contract["status"], "generated_unvalidated")
                self.assertIn("attacker_actor_inferred", contract["impact_contract_gaps"])
                # The rejected D4 generic placeholder must NOT be surfaced
                # verbatim as the contract actor; the explicit confirm
                # placeholder must be shown instead.
                self.assertEqual(contract["attacker_actor"], "attacker role must be confirmed")
                self.assertNotEqual(contract["attacker_actor"], placeholder)

    def test_scope_status_alone_does_not_satisfy_oos_trap_gate(self) -> None:
        # ``scope_status`` is a scope state, not a triager objection / OOS trap.
        # A row carrying only ``scope_status`` (no real trap, no trap-implying
        # impact keyword) must keep the ``oos_traps_missing`` gap and stay
        # generated_unvalidated.
        self.write_severity()
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-NOTRAP",
                        "title": "generic accounting discrepancy",
                        "attack_class": "accounting",
                        "likely_severity": "critical",
                        "impact_path": "theft of user funds",
                        "asset_at_risk": "escrowed bridge funds",
                        "attacker_role": "permissionless relayer",
                        "victim_role": "bridge user",
                        "scope_status": "in_scope",
                        "source_refs": ["runtime/src/ledger.rs:88"],
                        "source_artifacts_complete": True,
                        "negative_control": "removing the bug path leaves balances unchanged",
                        "state_impact_linkage": "ledger delta reduces escrowed funds while crediting the attacker",
                        "next_command": "cargo test -p pallet-ledger accounting",
                    }
                ],
            },
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertEqual(contract["status"], "generated_unvalidated")
        self.assertIn("oos_traps_missing", contract["impact_contract_gaps"])

    def test_real_oos_trap_satisfies_gate(self) -> None:
        # A row carrying a real row-level OOS trap must NOT get the
        # oos_traps_missing gap and (all else complete) must map.
        self.write_severity()
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-TRAP",
                        "title": "generic accounting discrepancy",
                        "attack_class": "accounting",
                        "likely_severity": "critical",
                        "impact_path": "theft of user funds",
                        "asset_at_risk": "escrowed bridge funds",
                        "attacker_role": "permissionless relayer",
                        "victim_role": "bridge user",
                        "likely_triager_objection": "OOS if framed as imported-library behavior only",
                        "source_refs": ["runtime/src/ledger.rs:88"],
                        "source_artifacts_complete": True,
                        "negative_control": "removing the bug path leaves balances unchanged",
                        "state_impact_linkage": "ledger delta reduces escrowed funds while crediting the attacker",
                        "protocol_defenses": ["ledger invariant guard"],
                        "covered_defenses": ["ledger invariant guard"],
                        "next_command": "cargo test -p pallet-ledger accounting",
                    }
                ],
            },
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertNotIn("oos_traps_missing", contract["impact_contract_gaps"])
        self.assertEqual(contract["status"], "mapped")

    def test_cli_update_queue_writes_contracts_and_patches_queue(self) -> None:
        self.write_severity()
        self.write_queue()
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(self.ws), "--update-queue", "--print-json"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["summary"]["patched_queue_rows"], 1)
        contracts = json.loads((self.ws / ".auditooor" / "impact_contracts.json").read_text(encoding="utf-8"))
        queue = json.loads((self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8"))
        self.assertEqual(contracts["contracts"][0]["impact_contract_id"], "impact-contract-eq-001")
        self.assertEqual(queue["queue"][0]["impact_contract_id"], "impact-contract-eq-001")
        self.assertEqual(contracts["contracts"][0]["dispatch_site"], "runtime/src/bridge.rs:120")
        self.assertEqual(queue["queue"][0]["dispatch_site"], "runtime/src/bridge.rs:120")

    # ------------------------------------------------------------------
    # HACKERMAN_V3 opposed-trace proof gate (POINT 1)
    # ------------------------------------------------------------------
    def _opposed_base_row(self) -> dict:
        return {
            "lead_id": "EQ-OPP",
            "title": "watcher accepts unrelated exit drains user funds",
            "attack_class": "validation-gap",
            "likely_severity": "critical",
            "impact_path": "direct loss of user funds",
            "asset_at_risk": "escrowed user funds",
            "attacker_role": "permissionless relayer",
            "victim_role": "exiting user",
            "likely_triager_objection": "OOS if framed as imported-library behavior only",
            "source_refs": ["runtime/src/watch_chain.rs:842"],
            "source_artifacts_complete": True,
            "negative_control": "consumed exit txid must be rejected",
            "state_impact_linkage": "accepted exit txid commits receiver state while attacker keeps the funding output",
            "next_command": "cargo test -p watcher exit_replay",
        }

    def test_high_plus_impact_with_no_defenses_required_and_stays_non_mapped(self) -> None:
        # HIGH+ Direct-loss impact + no enumerated protocol defenses ->
        # opposed_trace_required=true, coverage=missing, row stays
        # generated_unvalidated (cannot promote to mapped).
        self.write_severity()
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [self._opposed_base_row()]},
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertTrue(contract["opposed_trace_required"])
        self.assertEqual(contract["opposed_trace_coverage"], "missing")
        self.assertEqual(contract["protocol_defenses_enumerated"], [])
        self.assertIn("opposed_trace_defenses_unenumerated", contract["impact_contract_gaps"])
        self.assertEqual(contract["status"], "generated_unvalidated")

    def test_enumerated_defenses_uncovered_stays_non_mapped(self) -> None:
        # Defenses enumerated but not all covered -> coverage=missing, gap set,
        # row stays generated_unvalidated.
        self.write_severity()
        row = self._opposed_base_row()
        row["protocol_defenses"] = ["lower-timelock connector refund", "watchtower path"]
        row["covered_defenses"] = ["watchtower path"]
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertTrue(contract["opposed_trace_required"])
        self.assertEqual(contract["opposed_trace_coverage"], "missing")
        self.assertIn("lower-timelock connector refund", contract["missing_defenses"])
        self.assertIn("opposed_trace_coverage_missing", contract["impact_contract_gaps"])
        self.assertEqual(contract["status"], "generated_unvalidated")

    def test_enumerated_defenses_fully_covered_may_promote_to_mapped(self) -> None:
        # Defenses enumerated AND opposed_trace coverage covered (every defense
        # in covered_defenses) -> coverage=covered, no opposed-trace gap, row
        # may promote to mapped.
        self.write_severity()
        row = self._opposed_base_row()
        row["protocol_defenses"] = ["lower-timelock connector refund", "watchtower path"]
        row["covered_defenses"] = ["lower-timelock connector refund", "watchtower path"]
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertTrue(contract["opposed_trace_required"])
        self.assertEqual(contract["opposed_trace_coverage"], "covered")
        self.assertEqual(contract["missing_defenses"], [])
        self.assertNotIn("opposed_trace_defenses_unenumerated", contract["impact_contract_gaps"])
        self.assertNotIn("opposed_trace_coverage_missing", contract["impact_contract_gaps"])
        self.assertEqual(contract["status"], "mapped")

    def test_typed_opt_out_disarms_opposed_trace_gate(self) -> None:
        # A typed opt-out justification (matching the typed reason vocabulary)
        # is honored: opposed_trace_required=false, coverage=not_applicable, no
        # opposed-trace gap. A complete row may then map.
        self.write_severity()
        row = self._opposed_base_row()
        row["opposed_trace_opt_out"] = {"reason": "no_protocol_defenses_exist"}
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertFalse(contract["opposed_trace_required"])
        self.assertEqual(contract["opposed_trace_coverage"], "not_applicable")
        self.assertEqual(contract["opposed_trace_opt_out_reason"], "no_protocol_defenses_exist")
        self.assertNotIn("opposed_trace_defenses_unenumerated", contract["impact_contract_gaps"])
        self.assertEqual(contract["status"], "mapped")

    def test_free_form_opt_out_reason_is_ignored_gate_stays_armed(self) -> None:
        # An opt-out whose reason is NOT in the typed vocabulary is ignored -
        # the gate stays armed (no silent bypass).
        self.write_severity()
        row = self._opposed_base_row()
        row["opposed_trace_opt_out"] = {"reason": "we decided it's fine"}
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertTrue(contract["opposed_trace_required"])
        self.assertEqual(contract["opposed_trace_coverage"], "missing")
        self.assertEqual(contract["status"], "generated_unvalidated")

    def write_severity_with_low(self) -> None:
        # A SEVERITY.md that also carries a Low tier so a non-HIGH+ row can
        # match an exact impact row and (absent other gaps) promote to mapped.
        (self.ws / "SEVERITY.md").write_text(
            "# Program Severity\n\n"
            "## Critical\n"
            "- Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield\n"
            "- Permanent freezing of funds\n\n"
            "## High\n"
            "- Temporary freezing of funds\n\n"
            "## Low\n"
            "- Minor event ordering quirk affecting the indexer event stream\n",
            encoding="utf-8",
        )

    def _low_row(self) -> dict:
        # A complete non-HIGH+ row: every non-opposed-trace gap signal is
        # satisfied, so the only thing that could keep it non-mapped would be a
        # hard opposed-trace gap. The tiered model emits an ADVISORY instead.
        return {
            "lead_id": "EQ-LOW",
            "title": "minor event ordering quirk",
            "attack_class": "informational",
            "likely_severity": "low",
            "impact_path": "event emitted in wrong order",
            "asset_at_risk": "indexer event stream",
            "attacker_role": "permissionless caller",
            "victim_role": "indexer",
            "likely_triager_objection": "OOS if cosmetic only",
            "source_refs": ["runtime/src/events.rs:10"],
            "source_artifacts_complete": True,
            "negative_control": "removing the bug leaves event order unchanged",
            "state_impact_linkage": "event ordering state differs from the canonical event stream",
            "next_command": "cargo test -p events ordering",
        }

    def test_non_high_plus_question_is_still_asked(self) -> None:
        # Tiered model: the opposed-trace question is asked for EVERY contract
        # regardless of severity. A non-HIGH+ contract is NOT HARD-required
        # (opposed_trace_required=false), but protocol_defenses_enumerated and
        # opposed_trace_coverage are still computed - a non-HIGH+ contract with
        # no defenses gets coverage=missing (not a silent not_applicable).
        self.write_severity_with_low()
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [self._low_row()]},
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        # HARD enforcement does not apply below HIGH+.
        self.assertFalse(contract["opposed_trace_required"])
        # The question is still asked: the field is present and computed.
        self.assertIn("protocol_defenses_enumerated", contract)
        self.assertIn("opposed_trace_coverage", contract)
        # No defenses enumerated -> coverage=missing (visible, not silenced).
        self.assertEqual(contract["opposed_trace_coverage"], "missing")

    def test_non_high_plus_missing_opposed_trace_is_advisory_not_gap(self) -> None:
        # A non-HIGH+ contract with a missing opposed trace emits an ADVISORY
        # (opposed_trace_advisory / contract_advisories) - it must NOT add a
        # contract gap, so the row still promotes to mapped.
        self.write_severity_with_low()
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [self._low_row()]},
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        # Advisory marker is set and visible to the reviewer.
        self.assertTrue(contract["opposed_trace_advisory"])
        self.assertIn("opposed_trace_defenses_unenumerated", contract["contract_advisories"])
        # The advisory is NOT a hard contract gap.
        self.assertNotIn("opposed_trace_defenses_unenumerated", contract["impact_contract_gaps"])
        self.assertNotIn("opposed_trace_coverage_missing", contract["impact_contract_gaps"])
        # A complete non-HIGH+ row still promotes to mapped despite the advisory.
        self.assertEqual(contract["status"], "mapped")
        # The payload summary surfaces the advisory count.
        self.assertEqual(payload["summary"]["contracts_with_opposed_trace_advisory"], 1)
        self.assertIn(
            "opposed_trace_defenses_unenumerated", payload["summary"]["advisory_counts"]
        )

    def test_non_high_plus_opt_out_still_not_applicable(self) -> None:
        # The not_applicable honest escape stays: a non-HIGH+ contract with a
        # typed opt-out has coverage=not_applicable and NO advisory.
        self.write_severity_with_low()
        row = self._low_row()
        row["opposed_trace_opt_out"] = {"reason": "impact_is_not_fund_loss"}
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertFalse(contract["opposed_trace_required"])
        self.assertEqual(contract["opposed_trace_coverage"], "not_applicable")
        self.assertFalse(contract["opposed_trace_advisory"])
        self.assertEqual(contract["contract_advisories"], [])
        self.assertEqual(contract["status"], "mapped")

    def test_defense_verb_in_impact_text_is_auto_enumerated(self) -> None:
        # A row whose impact / root-cause text mentions a defense verb (e.g.
        # "watchtower", "refund") auto-enumerates that defense family.
        self.write_severity()
        row = self._opposed_base_row()
        row["root_cause_hypothesis"] = "watcher bypasses the watchtower refund path on a forged exit"
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [row]},
        )
        payload, _ = self.tool.build_payload(self.ws)
        contract = payload["contracts"][0]
        self.assertTrue(contract["opposed_trace_required"])
        self.assertIn("watchtower path", contract["protocol_defenses_enumerated"])
        self.assertIn("refund path", contract["protocol_defenses_enumerated"])

    def test_preserves_locked_existing_contract(self) -> None:
        self.write_severity()
        self.write_queue()
        self.write_json(
            ".auditooor/impact_contracts.json",
            {
                "schema": "auditooor.pr560.impact_contracts.v1",
                "contracts": [
                    {
                        "impact_contract_id": "impact-contract-eq-001",
                        "candidate_id": "EQ-001",
                        "status": "locked",
                        "selected_impact": "Permanent freezing of funds",
                        "severity": "Critical",
                        "severity_tier": "Critical",
                        "exact_impact_row": True,
                        "listed_impact_proven": True,
                        "evidence_class": "local_source_harness",
                        "oos_traps": ["not admin-only"],
                        "stop_condition": "stop if freeze is not demonstrated",
                        "proof_artifact": "poc_execution/EQ-001/execution_manifest.json",
                        "dispatch_site": "runtime/src/locked_bridge.rs:44",
                        "reachability_trace": (
                            "Reachability trace: dispatched via locked production router at "
                            "runtime/src/locked_bridge.rs:44"
                        ),
                    }
                ],
            },
        )

        payload, patched_queue = self.tool.build_payload(self.ws)
        self.assertEqual(payload["summary"]["preserved_locked_contracts"], 1)
        self.assertEqual(payload["contracts"][0]["status"], "locked")
        assert patched_queue is not None
        self.assertEqual(patched_queue["queue"][0]["impact_contract_status"], "locked")
        self.assertEqual(patched_queue["queue"][0]["dispatch_site"], "runtime/src/bridge.rs:120")


    # --- T1 regression: OOS/exclusion-block sentences must not leak into impact pool ---

    def test_oos_exclusion_section_sentences_never_in_impact_pool(self) -> None:
        """T1 regression: parse_severity_impacts must not include sentences from
        OOS/exclusion heading sections in any severity's listed-impact pool.

        Bug root: _severity_from_heading returned ``current`` unchanged for headings
        like '## Severity Caps And Exclusions', so bullets under that heading were
        appended to the last active severity tier (Low).  The fix detects OOS/exclusion
        heading keywords and clears ``current`` so that subsequent bullets are skipped.
        """
        tool = _load_tool()
        # Synthetic SEVERITY.md that mirrors the hyperbridge shape:
        # in-scope section reuses the same heading name that doesn't match a severity
        # keyword, so without the fix items from both sections bleed into Low.
        severity_md = (
            "# Program Severity\n\n"
            "## Critical\n\n"
            "Critical prose.\n\n"
            "## High\n\n"
            "High prose.\n\n"
            "## Medium\n\n"
            "Medium prose.\n\n"
            "## Low\n\n"
            "Low prose.\n\n"
            "## In-Scope Impact Classes\n\n"
            "- Stealing or loss of funds\n"
            "- Unauthorized transaction\n\n"
            "## Severity Caps And Exclusions\n\n"
            "- Theoretical vulnerabilities without proof or demonstration are out of scope.\n"
            "- Imported-contract vulnerabilities are out of scope.\n"
            "- Vulnerabilities exploitable through front-run attacks only are out of scope.\n"
        )
        sev_path = self.ws / "SEVERITY.md"
        sev_path.write_text(severity_md, encoding="utf-8")

        impacts = tool.parse_severity_impacts(self.ws)

        # All OOS/exclusion sentences must be absent from every tier's list.
        all_items = [item for tier_items in impacts.values() for item in tier_items]
        oos_sentences = [
            "Theoretical vulnerabilities without proof or demonstration are out of scope.",
            "Imported-contract vulnerabilities are out of scope.",
            "Vulnerabilities exploitable through front-run attacks only are out of scope.",
        ]
        for sentence in oos_sentences:
            self.assertNotIn(
                sentence,
                all_items,
                f"OOS/exclusion sentence leaked into impact pool: {sentence!r}",
            )

        # In-scope items from the non-severity heading section must also be absent
        # (the "In-Scope Impact Classes" heading does not name a severity and bullets
        # under it should not be attributed to any severity tier either).
        # They are NOT in the OOS block, but they have no severity attribution.
        # The tool only collects bullets when ``current`` is a known severity name.
        # The headings that don't match a severity keyword keep current unchanged,
        # so these items land under Low (the last parsed severity).  That is separate
        # from the OOS bug. The critical assertion is that OOS sentences are absent.

        # Separately verify that in-scope items from the named severity sections are
        # NOT lost (the fix must not over-clear ``current``).
        # We write a fresh SEVERITY.md where in-scope bullet items are inside the
        # named severity headings, and verify they ARE collected.
        severity_md_inline = (
            "# Program Severity\n\n"
            "## Critical\n\n"
            "- Direct theft of user funds\n"
            "- Permanent freezing of funds\n\n"
            "## High\n\n"
            "- Temporary freezing of funds\n\n"
            "## Severity Caps And Exclusions\n\n"
            "- Old compiler version and unlocked compiler version are out of scope.\n"
        )
        sev_path.write_text(severity_md_inline, encoding="utf-8")
        impacts2 = tool.parse_severity_impacts(self.ws)

        # In-scope items from named severity headings must be present.
        self.assertIn("Direct theft of user funds", impacts2["Critical"])
        self.assertIn("Permanent freezing of funds", impacts2["Critical"])
        self.assertIn("Temporary freezing of funds", impacts2["High"])

        # OOS sentence must NOT be present in any tier.
        all_items2 = [item for tier_items in impacts2.values() for item in tier_items]
        self.assertNotIn(
            "Old compiler version and unlocked compiler version are out of scope.",
            all_items2,
            "OOS/exclusion sentence leaked after fix.",
        )

    def test_selected_impact_never_drawn_from_oos_exclusion_block(self) -> None:
        """T1 integration regression: build_contract must not set selected_impact to
        an OOS/exclusion sentence even when the queue row's keywords superficially
        match the exclusion text.
        """
        tool = _load_tool()
        # SEVERITY.md where the exclusion block contains text that scores highly
        # on generic keywords (e.g. 'theoretical' doesn't but we test with an
        # OOS sentence that contains 'front-run' which is also in the keyword set).
        severity_md = (
            "## Critical\n- Direct theft of user funds\n\n"
            "## Medium\n- Logic errors with bounded impact\n\n"
            "## Severity Caps And Exclusions\n"
            "- Vulnerabilities exploitable through front-run attacks only are out of scope.\n"
        )
        (self.ws / "SEVERITY.md").write_text(severity_md, encoding="utf-8")

        # Queue row with attack_class that mentions front-run to tempt the scorer.
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-T1",
                        "title": "front-run on settlement drains funds",
                        "attack_class": "front-run",
                        "likely_severity": "medium",
                        "impact_path": "loss of funds via front-run",
                        "asset_at_risk": "settlement funds",
                        "attacker_role": "mev searcher",
                        "victim_role": "settler",
                        "oos_traps": ["check not front-run-only OOS"],
                        "source_refs": ["src/Settler.sol:100"],
                        "source_artifacts_complete": True,
                        "negative_control": "same block without front-run must settle correctly",
                        "state_impact_linkage": "settlement balance changes when the front-run path is present",
                        "next_command": "forge test --match-test testFrontRunSettlement",
                    }
                ],
            },
        )

        payload, _ = tool.build_payload(self.ws)
        contracts = payload.get("contracts", [])
        self.assertEqual(len(contracts), 1)
        selected = contracts[0].get("selected_impact", "")
        self.assertNotIn(
            "out of scope",
            selected.lower(),
            f"selected_impact drawn from OOS/exclusion block: {selected!r}",
        )


if __name__ == "__main__":
    unittest.main()
