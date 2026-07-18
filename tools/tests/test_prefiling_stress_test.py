from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "prefiling-stress-test.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("prefiling_stress_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["prefiling_stress_test"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


class PrefilingStressTest(unittest.TestCase):
    def _typed_queue(self) -> dict:
        parent = ["zdo-parent", "zdr-revision"]
        return {
            "schema": "auditooor.exploit_queue.v1",
            "queue_role": "proof_tasks",
            "queue": [{
                "lead_id": "zdpq-lead",
                "obligation_id": parent[0],
                "revision_id": parent[1],
                "title": "Frozen typed proof lead",
                "likely_severity": "High",
                "proof_status": "needs_source",
                "zero_day_proof_projection": {
                    "schema": "auditooor.zero_day_proof_queue_projection.v1",
                    "freeze_receipt_id": "a" * 64,
                    "freeze_input_fingerprint": "b" * 64,
                    "obligation_source_row_sha256": "c" * 64,
                    "parent_ids": parent,
                    "selection_ordinal": 1,
                    "question_evidence": [{"question_id": "q0"}],
                },
                "zero_day_proof_admission": {
                    "freeze_receipt_id": "a" * 64,
                    "input_fingerprint": "b" * 64,
                    "obligation_source_row_sha256": "c" * 64,
                    "parent_ids": parent,
                },
            }],
            "zero_day_proof_admission": {
                "schema": "auditooor.zero_day_proof_admission.v1",
                "queue_role": "proof_tasks",
                "admission_id": "zdpa_" + "d" * 64,
                "input_queue_sha256": "e" * 64,
                "freeze_receipt_id": "a" * 64,
                "freeze_input_fingerprint": "b" * 64,
                "admitted_count": 1,
                "admitted_parents": [{"obligation_id": parent[0], "revision_id": parent[1]}],
            },
        }

    def test_typed_terminal_rows_require_exact_envelope_record(self) -> None:
        queue = self._typed_queue()
        entry = tool._typed_queue_entries(queue)["zdpq-lead"]
        row = queue["queue"][0]
        row["proof_status"] = "closed_negative"

        self.assertFalse(tool._is_terminal_queue_row(row, entry))

        row["terminal_join"] = {
            "schema": tool.TYPED_TERMINAL_SCHEMA,
            "parent_ids": ["zdo-parent", "zdr-revision"],
            "envelope_id": entry["envelope_id"],
            "evidence_ref": "src/Vault.sol:L42",
        }
        self.assertTrue(tool._is_terminal_queue_row(row, entry))

        row["terminal_join"]["envelope_id"] = "zdpe-wrong"
        self.assertFalse(tool._is_terminal_queue_row(row, entry))

    def test_typed_queue_rejects_legacy_entries_bucket(self) -> None:
        queue = self._typed_queue()
        queue["entries"] = [{"lead_id": "legacy-discovery-row"}]
        with self.assertRaisesRegex(ValueError, "typed_proof_envelope_legacy_entries_present"):
            tool._typed_queue_entries(queue)

    def test_cli_skips_typed_terminal_only_with_exact_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            queue = self._typed_queue()
            entry = tool._typed_queue_entries(queue)["zdpq-lead"]
            row = queue["queue"][0]
            row["proof_status"] = "closed_negative"
            row["terminal_join"] = {
                "schema": tool.TYPED_TERMINAL_SCHEMA,
                "parent_ids": ["zdo-parent", "zdr-revision"],
                "envelope_id": entry["envelope_id"],
                "evidence_ref": "src/Vault.sol:L42",
            }
            queue_path = root / "exploit_queue.json"
            queue_path.write_text(json.dumps(queue), encoding="utf-8")
            envelope = tool._load_typed_envelope_tool()
            envelope.materialize(
                root, queue_path, root / ".auditooor" / "zero_day_proof_envelope.json",
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--exploit-queue", str(queue_path),
                 "--workspace", str(root), "--strict"],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            payload = json.loads((root / ".auditooor" / "prefiling_stress_test.json").read_text(encoding="utf-8"))
            self.assertEqual(1, payload["terminal_rows_skipped"])
            self.assertEqual(0, payload["rows_assessed"])

    def test_clean_high_candidate_passes_and_emits_evidence_plan(self) -> None:
        row = {
            "lead_id": "EQ-CLEAN",
            "title": "Public withdraw drains vault user funds",
            "likely_severity": "High",
            "permissionless_action": "Unprivileged attacker calls withdraw(shareAmount) on VaultRouter.",
            "attacker_control": "known",
            "selected_impact": "Direct theft of user funds",
            "rubric_row": "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["contracts/VaultRouter.sol:120"],
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "pass")
        self.assertIn("end_to_end_runtime", result["evidence_plan"]["required_evidence_class"])
        self.assertEqual(result["questions"]["prior_disclosure"]["status"], "clean")

    def test_high_admin_dependency_fails_before_poc(self) -> None:
        row = {
            "lead_id": "EQ-ADMIN",
            "title": "Owner can drain fees",
            "likely_severity": "Critical",
            "permissionless_action": "Owner calls emergencyWithdraw after governance sets unsafe config.",
            "attacker_control": "partial",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("missing_or_vague_permissionless_action", result["blocked_reasons"])
        self.assertIn("privileged_mock_oos_or_synthetic_dependency_present", result["blocked_reasons"])

    def test_graph_sandwich_claim_requires_window_and_oos_distinction(self) -> None:
        row = {
            "lead_id": "GRAPH-SANDWICH",
            "title": "Graph curator sandwich extracts rewards",
            "likely_severity": "High",
            "permissionless_action": "Any address submits public curate and burn calls.",
            "attacker_control": "known",
            "rubric_row": "Theft of unclaimed yield",
            "dupe_risk": "low",
            "source_refs": ["contracts/Curation.sol:88"],
            "attacker_actor": "curator",
            "victim_actor": "subgraph signaler",
            "capital_lock": "1000 GRT locked for one block",
            "profit_loss": "attacker profit is the reward delta minus fees",
            "affected_amount_basis": "reward delta from curation pool accounting",
            "impact_path": "MEV sandwich around a curate call extracts rewards.",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("missing_execution_window_or_oos_distinction", result["blocked_reasons"])

    def test_graph_style_natural_network_activity_blocks_before_poc(self) -> None:
        row = {
            "lead_id": "GRAPH-NATURAL-ACTIVITY",
            "title": "Curator pre-positioning around owner publish extracts rewards",
            "likely_severity": "High",
            "permissionless_action": "Any address uses public curation and burn calls.",
            "attacker_control": "known",
            "rubric_row": "Theft of unclaimed yield",
            "dupe_risk": "low",
            "source_refs": ["contracts/L2Curation.sol:88"],
            "attacker_actor": "curator",
            "victim_actor": "subgraph signaler",
            "capital_lock": "1000 GRT locked for one block",
            "profit_loss": "attacker profit is the signal redemption delta minus gas",
            "affected_amount_basis": "curation pool accounting delta",
            "impact_path": (
                "The attacker pre-curates through permissionless curation before a publish transaction. "
                "This relies on natural network activity and a sandwich execution window; the draft has an OOS distinction "
                "but no independent protocol fault."
            ),
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("ambient_mev_without_protocol_fault_distinction", result["blocked_reasons"])
        self.assertIn("natural_network_activity_scope_risk", result["blocked_reasons"])

    def test_revert_style_protocol_fault_amplified_by_mev_passes_mev_gate(self) -> None:
        row = {
            "lead_id": "REVERT-INNER-SLIPPAGE",
            "title": "ZapIn zero inner slippage lets sandwich amplify protocol bug",
            "likely_severity": "High",
            "permissionless_action": "Any address calls public zapIn().",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "source_refs": ["src/periphery/StableSwapZapIn.sol:424"],
            "proof_path": "foundry",
            "attacker_actor": "external swapper",
            "victim_actor": "zap user",
            "capital_lock": "front-run swap capital",
            "profit_loss": "attacker profit is victim LP share value lost minus fees",
            "affected_amount_basis": "LP share balance delta",
            "impact_path": (
                "Same block execution window. OOS distinction: this is not merely MEV. "
                "The underlying protocol bug is zero inner minAmounts/minShares and broken internal slippage."
            ),
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "pass")
        self.assertNotIn("ambient_mev_without_protocol_fault_distinction", result["blocked_reasons"])
        self.assertNotIn("natural_network_activity_scope_risk", result["blocked_reasons"])

    def test_polymarket_reward_economics_requires_all_economic_fields(self) -> None:
        row = {
            "lead_id": "POLY-REWARDS",
            "title": "Polymarket reward extraction with admin pause uncertainty",
            "likely_severity": "High",
            "permissionless_action": "Any address places public orders to extract rewards; no admin action required.",
            "attacker_control": "known",
            "rubric_row": "Theft of unclaimed yield",
            "dupe_risk": "low",
            "impact_path": "Reward extraction drains trading incentives from victims.",
            "source_refs": ["src/Rewards.sol:44"],
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("missing_economics_proof_for_value_claim", result["blocked_reasons"])
        self.assertNotIn("privileged_mock_oos_or_synthetic_dependency_present", result["blocked_reasons"])
        self.assertIn("capital_lock_or_cost", result["questions"]["economics"]["missing_fields"])
        self.assertIn("profit_or_loss_statement", result["questions"]["economics"]["missing_fields"])

    def test_polymarket_style_negative_economics_and_actor_mismatch_block(self) -> None:
        row = {
            "lead_id": "POLY-198",
            "title": "Anyone steals the creator reward while market is flagged",
            "likely_severity": "High",
            "permissionless_action": "Any address calls priceDisputed during the flag window.",
            "attacker_control": "known",
            "rubric_row": "Theft of unclaimed yield",
            "dupe_risk": "low",
            "source_refs": ["src/UmaCtfAdapter.sol:198"],
            "attacker_actor": "external caller",
            "victim_actor": "market creator",
            "capital_lock": "UMA bond starts around 750 USD",
            "profit_loss": "Cost exceeds reward: typical creator rewards are 2-5 USD while UMA bonds start around 750 USD.",
            "affected_amount_basis": "creator reward amount",
            "impact_path": "The path targets the creator reward, but Polymarket is the only intended creator.",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("economically_negative_or_unprofitable_claim", result["blocked_reasons"])
        self.assertIn("intended_actor_mismatch", result["blocked_reasons"])

    def test_nuva_self_created_admin_resource_does_not_fail_privilege_gate(self) -> None:
        row = {
            "lead_id": "NUVA-SELF-ADMIN",
            "title": "Self-created admin pool cannot be used as pre-existing privilege",
            "likely_severity": "High",
            "permissionless_action": "Any address permissionlessly creates its own market and becomes admin of that self-created resource.",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["contracts/MarketFactory.sol:31"],
            "impact_path": "The non-privileged path is factory createMarket followed by public deposit accounting.",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "pass")
        self.assertNotIn("privileged_mock_oos_or_synthetic_dependency_present", result["blocked_reasons"])

    def test_pre_existing_admin_path_still_fails_privilege_gate(self) -> None:
        row = {
            "lead_id": "NUVA-PREEXISTING-ADMIN",
            "title": "Pre-existing admin pauses market before exploit",
            "likely_severity": "High",
            "permissionless_action": "The pre-existing admin pauses the market, then users cannot exit.",
            "attacker_control": "partial",
            "rubric_row": "Permanent freezing of funds",
            "dupe_risk": "low",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("privileged_mock_oos_or_synthetic_dependency_present", result["blocked_reasons"])

    def test_multiple_impacts_same_root_cause_requires_one_fix_discussion(self) -> None:
        row = {
            "lead_id": "ONE-FIX",
            "title": "Two impacts from the same root cause",
            "likely_severity": "High",
            "permissionless_action": "Any address calls public settle().",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["contracts/Settlement.sol:90"],
            "impact_path": "Multiple impacts share the same root cause: user fund theft and temporary insolvency.",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("missing_unified_report_or_one_fix_discussion", result["blocked_reasons"])

    def test_oos_asset_contract_impact_requires_primacy_justification(self) -> None:
        row = {
            "lead_id": "OOS-ASSET-PRIMACY",
            "title": "Unlisted asset causes in-contract loss",
            "likely_severity": "High",
            "permissionless_action": "Any address deposits an unsupported asset through the public router.",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["contracts/Router.sol:77"],
            "impact_path": "The impact uses an out-of-scope asset to trigger accounting loss.",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("missing_primacy_of_impact_for_oos_asset_claim", result["blocked_reasons"])

    def test_mev_negation_and_admin_negation_pass(self) -> None:
        row = {
            "lead_id": "NEGATED-MEV-ADMIN",
            "title": "Public withdraw is not a sandwich attack",
            "likely_severity": "High",
            "permissionless_action": "Any address calls withdraw(); no admin action required.",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["contracts/Vault.sol:55"],
            "impact_path": "This is not a sandwich attack and has no admin action required.",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "pass")
        self.assertNotIn("missing_execution_window_or_oos_distinction", result["blocked_reasons"])
        self.assertNotIn("privileged_mock_oos_or_synthetic_dependency_present", result["blocked_reasons"])

    def test_markdown_bold_fields_and_negated_cosmos_contamination_parse(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            draft = Path(td) / "nuva-expdec.md"
            draft.write_text(
                "\n".join(
                    [
                        "# NUVA ExpDec causes chain halt",
                        "",
                        "**Severity:** Critical",
                        "",
                        "## Platform Selectors",
                        "- Impact(s): Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                        "",
                        "A fresh non-privileged account uses normal fee-paying messages. The attacker calls MsgCreateVault,",
                        "becomes Admin only over the attacker-created vault, and uses public update-rate messages.",
                        "",
                        "The production profile uses GoLevelDB. No MemDB-only shortcut, no reflection, no direct DB key injection,",
                        "and no mock oracle are used.",
                        "",
                        "## Impact Contract",
                        "- victim: non-attacker depositor",
                        "- attacker: fresh non-privileged account",
                        "- source-proof: src/vault/utils/math.go:13-26",
                        "",
                        "## Distinction From Prior Findings",
                        "Prior audits discuss marker NAV, but this is novel and a different root cause.",
                    ]
                ),
                encoding="utf-8",
            )
            result = tool.assess(tool._draft_to_row(draft), "draft")
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["claimed_severity"], "critical")
            self.assertNotIn("missing_or_vague_permissionless_action", result["blocked_reasons"])
            self.assertNotIn("privileged_mock_oos_or_synthetic_dependency_present", result["blocked_reasons"])
            self.assertEqual(result["questions"]["prior_disclosure"]["status"], "clean")

    def test_workspace_cosmos_harness_preflight_blocker_is_specific(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            exec_dir = workspace / "poc_execution" / "eq-003"
            exec_dir.mkdir(parents=True)
            (exec_dir / "cosmos_production_harness_exec.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.cosmos_production_harness_exec.v1",
                        "tool": "cosmos-production-harness-exec",
                        "preflight": {
                            "execution_allowed": False,
                            "phase_a_verdict": "needs_work",
                            "phase_b_blocking_gap_count": 3,
                        },
                        "execution": {"attempted": False},
                        "runtime_proof_claimed": False,
                    }
                ),
                encoding="utf-8",
            )
            row = {
                "lead_id": "EQ-003",
                "title": "Cosmos withdrawal migration griefing",
                "likely_severity": "Critical",
                "permissionless_action": "Any address submits a public MsgMigrateWithdrawal.",
                "attacker_control": "known",
                "rubric_row": "Permanent freezing of funds",
                "dupe_risk": "low",
                "proof_path": "foundry",
                "source_refs": ["x/withdrawal/keeper/msg_server.go:10"],
            }
            result = tool.assess(row, "candidate_row", workspace=workspace)
            self.assertEqual(result["verdict"], "fail")
            self.assertIn("cosmos_harness_preflight_blocked", result["blocked_reasons"])
            self.assertIn("production_harness_execution_not_attempted", result["blocked_reasons"])
            self.assertIn("harness_domain_mismatch", result["blocked_reasons"])

    def test_action_must_name_permissionless_actor_when_attacker_control_missing(self) -> None:
        row = {
            "lead_id": "EQ-VAGUE",
            "title": "Withdraw drains vault",
            "likely_severity": "High",
            "permissionless_action": "Caller invokes withdraw().",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("missing_or_vague_permissionless_action", result["blocked_reasons"])

    def test_generic_dos_candidate_fails_oos_dependency(self) -> None:
        row = {
            "lead_id": "DYDX-GENERIC-DOS",
            "title": "Generic DoS through CheckTx RPC pressure",
            "likely_severity": "High",
            "permissionless_action": "Any account floods CheckTx with transactions.",
            "attacker_control": "known",
            "rubric_row": "Network-level liveness failure",
            "dupe_risk": "low",
            "blockers": ["generic DoS without production matching-engine impact"],
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("privileged_mock_oos_or_synthetic_dependency_present", result["blocked_reasons"])

    def test_network_claim_requires_multivalidator_restart_and_persistent_profile(self) -> None:
        row = {
            "lead_id": "COSMOS-HALT",
            "title": "BeginBlocker Int overflow causes chain halt",
            "likely_severity": "Critical",
            "permissionless_action": "Unprivileged user submits MsgSwapIn that stores poisoned interest state.",
            "attacker_control": "known",
            "rubric_row": "Permanent freezing of funds",
            "dupe_risk": "low",
            "proof_path": "go test production profile",
        }
        result = tool.assess(row, "candidate_row")
        reqs = "\n".join(result["evidence_plan"]["requirements"])
        self.assertEqual(result["verdict"], "pass")
        self.assertIn("multi-validator", reqs)
        self.assertIn("restart behavior", reqs)
        self.assertIn("persistent backend", reqs)

    def test_prior_disclosure_not_checked_fails_high_plus(self) -> None:
        row = {
            "lead_id": "NO-DUPE-CHECK",
            "title": "Public redeem steals unclaimed yield",
            "likely_severity": "High",
            "permissionless_action": "Any address calls redeem() after yield accrues.",
            "attacker_control": "known",
            "rubric_row": "Theft of unclaimed yield",
            "proof_path": "foundry",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("prior_disclosure_not_checked", result["blocked_reasons"])

    def test_rubric_row_must_match_severity_file_when_provided(self) -> None:
        row = {
            "lead_id": "BAD-RUBRIC",
            "title": "Public withdraw drains vault user funds",
            "likely_severity": "High",
            "permissionless_action": "Unprivileged attacker calls withdraw(shareAmount).",
            "attacker_control": "known",
            "rubric_row": "Generic high severity words",
            "dupe_risk": "low",
            "proof_path": "foundry",
        }
        result = tool.assess(
            row,
            "candidate_row",
            severity_text="High\n- Direct theft of any user funds\n",
        )
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("rubric_row_not_found_in_severity_file", result["blocked_reasons"])

    # ------------------------------------------------------------------
    # HACKERMAN V3 Lane A4 - economic-viability and actor-model gate.
    # ------------------------------------------------------------------

    def test_a4_polymarket_198_steal_reward_routes_to_blocked_by_economics(self) -> None:
        """Polymarket #198 anchor: a steal-reward path whose extractable value
        ($2-5) is below the required UMA bond (~$750) AND is only reachable
        after an admin pause must route to blocked_by_economics, not PoC."""
        row = {
            "lead_id": "POLY-198",
            "title": "Anyone steals the creator reward while the market is flagged",
            "likely_severity": "High",
            "permissionless_action": "Any address calls priceDisputed during the flag window.",
            "attacker_control": "known",
            "rubric_row": "Theft of unclaimed yield",
            "dupe_risk": "low",
            "source_refs": ["src/UmaCtfAdapter.sol:198"],
            "attacker_actor": "external caller",
            "victim_actor": "market creator",
            "extractable_value": "$3",
            "reward_amount": "$3 creator reward",
            "required_bond": "$750",
            "capital_lock": "UMA dispute bond required",
            "profit_loss": "net loss after the bond",
            "affected_amount_basis": "creator reward amount",
            "impact_path": (
                "The path only exists after the team pauses the market, and it "
                "targets the creator reward."
            ),
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["verdict_route"], "blocked_by_economics")
        self.assertIn("extractable_value_below_required_cost", result["blocked_reasons"])
        self.assertIn("admin_pause_or_team_action_prerequisite", result["blocked_reasons"])
        self.assertIn("intended_actor_mismatch", result["blocked_reasons"])
        viability = result["questions"]["economic_viability"]
        self.assertEqual(viability["net_economics"], "negative")
        self.assertEqual(viability["extractable_value_usd"], 3.0)
        self.assertEqual(viability["required_cost_usd"], 750.0)
        self.assertEqual(result["questions"]["admin_pause_prerequisite"]["status"], "fail")

    def test_a4_value_below_cost_via_prose_numbers_blocks(self) -> None:
        """The numeric comparison works off currency-anchored prose, not just
        typed fields - $4 reward vs $800 bond is still net-negative."""
        row = {
            "lead_id": "A4-PROSE-NEG",
            "title": "Reward extraction from a flagged market",
            "likely_severity": "Critical",
            "permissionless_action": "Any address calls the public claim path.",
            "attacker_control": "known",
            "rubric_row": "Theft of unclaimed yield",
            "dupe_risk": "low",
            "source_refs": ["src/Adapter.sol:120"],
            "attacker_actor": "external caller",
            "victim_actor": "protocol",
            "capital_lock": "bond posted",
            "profit_loss": "see model",
            "affected_amount_basis": "reward pool",
            "impact_path": (
                "The reward payout is about $4 while the required bond costs $800, "
                "so the attacker takes a net loss."
            ),
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["verdict_route"], "blocked_by_economics")
        self.assertIn("extractable_value_below_required_cost", result["blocked_reasons"])

    def test_a4_admin_pause_only_path_routes_to_blocked_by_scope(self) -> None:
        """A liquidation path reachable only after an emergency admin pause is
        a scope problem - route to blocked_by_scope before PoC."""
        row = {
            "lead_id": "A4-PAUSE-SCOPE",
            "title": "Liquidation grief after emergency pause",
            "likely_severity": "High",
            "permissionless_action": "Any address calls liquidate() on a paused market.",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["src/Liquidator.sol:60"],
            "attacker_actor": "external liquidator",
            "victim_actor": "borrower",
            "extractable_value": "$10k",
            "required_cost": "$1k gas and capital",
            "capital_lock": "$1k flash-loan fee",
            "profit_loss": "net positive once reachable",
            "affected_amount_basis": "borrower collateral",
            "impact_path": (
                "The bug only exists after the team triggers an emergency pause. "
                "Same block execution window. OOS distinction: this is not merely "
                "MEV - the underlying protocol bug is broken internal slippage "
                "independent of ordinary MEV."
            ),
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["verdict_route"], "blocked_by_scope")
        self.assertIn("admin_pause_or_team_action_prerequisite", result["blocked_reasons"])
        self.assertNotIn("extractable_value_below_required_cost", result["blocked_reasons"])

    def test_a4_profitable_non_self_liquidation_path_passes(self) -> None:
        """A genuinely profitable, permissionless, non-self liquidation/oracle
        path with positive economics passes the A4 gate."""
        row = {
            "lead_id": "A4-PROFIT",
            "title": "Liquidator exploits a stale oracle to seize borrower collateral",
            "likely_severity": "High",
            "permissionless_action": "Any address calls liquidate() after a stale oracle price.",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["src/Liquidator.sol:88"],
            "attacker_actor": "external liquidator",
            "victim_actor": "borrower",
            "extractable_value": "$50k",
            "required_cost": "$2k gas and capital",
            "capital_lock": "$2k flash-loan fee",
            "profit_loss": "net positive ~$48k for the attacker",
            "affected_amount_basis": "borrower collateral seized",
            "impact_path": (
                "Same block execution window. OOS distinction: this is not merely "
                "MEV - the underlying protocol bug is a stale oracle with no "
                "heartbeat check, independent of ordinary MEV ordering."
            ),
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["verdict_route"], "pass")
        self.assertEqual(result["blocked_reasons"], [])
        self.assertEqual(result["questions"]["economic_viability"]["net_economics"], "positive")

    def test_a4_liquidation_candidate_without_extraction_verb_still_requires_economics(self) -> None:
        """A4 widens economics relevance to MEV / liquidation / oracle / reward
        even when no explicit 'extraction' verb appears; a liquidation
        candidate missing the economics fields is blocked."""
        row = {
            "lead_id": "A4-LIQ-NO-ECON",
            "title": "Liquidation ordering lets the keeper seize collateral",
            "likely_severity": "High",
            "permissionless_action": "Any address calls the public liquidate() entrypoint.",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["src/Liquidator.sol:140"],
            "impact_path": (
                "A liquidation against a borrower position settles before the "
                "oracle update window closes."
            ),
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("missing_economics_proof_for_value_claim", result["blocked_reasons"])
        self.assertTrue(result["questions"]["economics"]["economics_relevant"])

    def test_a4_non_economics_direct_theft_does_not_require_economics_fields(self) -> None:
        """A plain withdraw() direct-theft finding is NOT a value-extraction /
        yield / MEV / liquidation / oracle / reward path - it must not be
        forced through the economics-fields gate (regression guard)."""
        row = {
            "lead_id": "A4-PLAIN-THEFT",
            "title": "Public withdraw drains vault user funds",
            "likely_severity": "High",
            "permissionless_action": "Unprivileged attacker calls withdraw(shareAmount) on VaultRouter.",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["contracts/VaultRouter.sol:120"],
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "pass")
        self.assertFalse(result["questions"]["economics"]["economics_relevant"])
        self.assertNotIn("missing_economics_proof_for_value_claim", result["blocked_reasons"])

    def test_a4_economics_relevance_from_attack_class_tag(self) -> None:
        """Economics relevance is also picked up from a typed attack_class /
        tags field, not only from prose."""
        row = {
            "lead_id": "A4-TAG",
            "title": "Ordering bug in the settlement path",
            "likely_severity": "High",
            "permissionless_action": "Any address calls the public settle() path.",
            "attacker_control": "known",
            "rubric_row": "Direct theft of any user funds",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["src/Settle.sol:10"],
            "attack_class": "mev-sandwich",
            "impact_path": "Settlement ordering shifts proceeds between callers.",
        }
        result = tool.assess(row, "candidate_row")
        self.assertTrue(result["questions"]["economics"]["economics_relevant"])
        self.assertIn("missing_economics_proof_for_value_claim", result["blocked_reasons"])

    def test_a4_negated_admin_pause_does_not_fire(self) -> None:
        """A draft explicitly stating no admin pause is required must not trip
        the admin-pause prerequisite gate."""
        row = {
            "lead_id": "A4-NO-PAUSE",
            "title": "Reward extraction with no admin dependency",
            "likely_severity": "High",
            "permissionless_action": "Any address calls the public reward claim; no admin action required.",
            "attacker_control": "known",
            "rubric_row": "Theft of unclaimed yield",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["src/Rewards.sol:44"],
            "attacker_actor": "external caller",
            "victim_actor": "another depositor",
            "extractable_value": "$5k",
            "required_cost": "$200 gas",
            "capital_lock": "$200 gas",
            "profit_loss": "net positive ~$4.8k",
            "affected_amount_basis": "reward pool delta",
            "impact_path": (
                "The reward extraction path is not paused and requires no team "
                "action; it is permissionless and not a sandwich."
            ),
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["questions"]["admin_pause_prerequisite"]["status"], "pass")

    def test_a4_low_severity_economics_negative_is_warn_not_block(self) -> None:
        """Below High the A4 numeric-economics signal is a warning, not a hard
        block - the gate only fails closed for High/Critical."""
        row = {
            "lead_id": "A4-LOW",
            "title": "Reward extraction edge case",
            "likely_severity": "Low",
            "permissionless_action": "Any address calls the public claim path.",
            "attacker_control": "known",
            "rubric_row": "Informational",
            "dupe_risk": "low",
            "source_refs": ["src/Rewards.sol:44"],
            "extractable_value": "$2",
            "required_cost": "$500 bond",
            "impact_path": "Reward extraction yields $2 against a $500 bond.",
        }
        result = tool.assess(row, "candidate_row")
        self.assertEqual(result["verdict"], "warn")
        self.assertIn("extractable_value_below_required_cost", result["warnings"])

    def test_reward_stream_future_emissions_only_routes_to_economics(self) -> None:
        row = {
            "lead_id": "RG-HELD-ERC20",
            "title": "ERC20 reward-token sniping by late depositor",
            "likely_severity": "High",
            "permissionless_action": "Any address deposits in the public staking vault.",
            "attacker_control": "known",
            "rubric_row": "Theft of unclaimed yield",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["contracts/staking/StakingVault.sol:339"],
            "attacker_actor": "late depositor",
            "victim_actor": "existing depositor",
            "capital_lock": "staking deposit",
            "profit_loss": "not modeled",
            "affected_amount_basis": "reward-token stream",
            "raw_draft_text": (
                "The PoC demonstrates late participation in future ERC20 "
                "reward-token stream emissions, but it does not prove unintended "
                "loss beyond the vault's live-supply reward-stream model."
            ),
        }

        result = tool.assess(row, "candidate_row")

        self.assertEqual(result["verdict"], "fail")
        self.assertIn(
            "outcome_lesson_future_reward_eligibility_not_accrued_reward_loss",
            result["economics_blockers"],
        )
        self.assertIn(
            "outcome_lesson_future_reward_eligibility_not_accrued_reward_loss",
            result["blocked_reasons"],
        )

    def test_draft_status_medium_high_applies_high_plus_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "rg-held-erc20-reward-token-sniping.md"
            draft.write_text(
                "# Held: ERC20 Reward-Token Sniping Variant\n\n"
                "Status: killed as standalone Medium/High, not paste-ready.\n\n"
                "Reason: the PoC demonstrates late participation in future ERC20 "
                "reward-token stream emissions, but it does not prove unintended loss "
                "beyond the vault's live-supply reward-stream model.\n",
                encoding="utf-8",
            )

            row = tool._draft_to_row(draft)
            result = tool.assess(row, "draft")

        self.assertEqual(result["claimed_severity"], "high")
        self.assertTrue(result["high_plus_gate_applied"])
        self.assertEqual(result["verdict"], "fail")
        self.assertIn(
            "outcome_lesson_future_reward_eligibility_not_accrued_reward_loss",
            result["blocked_reasons"],
        )

    def test_cli_writes_workspace_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            candidate = root / "row.json"
            candidate.write_text(json.dumps({
                "lead_id": "EQ-CLEAN",
                "title": "Public withdraw drains vault user funds",
                "likely_severity": "High",
                "permissionless_action": "Unprivileged attacker calls withdraw(shareAmount).",
                "attacker_control": "known",
                "rubric_row": "Direct theft of any user funds",
                "dupe_risk": "low",
                "proof_path": "foundry",
            }), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--candidate-row", str(candidate), "--workspace", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            artifact = root / ".auditooor" / "prefiling_stress_tests" / "EQ-CLEAN.prefiling_stress_test.json"
            self.assertTrue(artifact.is_file())
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "auditooor.prefiling_stress_test.v1")

    def test_cli_assesses_exploit_queue_and_writes_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            queue = root / "exploit_queue.json"
            queue.write_text(json.dumps({
                "queue": [
                    {
                        "lead_id": "EQ-CLEAN",
                        "title": "Public withdraw drains vault user funds",
                        "likely_severity": "High",
                        "permissionless_action": "Unprivileged attacker calls withdraw(shareAmount).",
                        "attacker_control": "known",
                        "rubric_row": "Direct theft of any user funds",
                        "dupe_risk": "low",
                        "proof_path": "foundry",
                    },
                    {
                        "lead_id": "EQ-BLOCK",
                        "title": "Admin sets unsafe config",
                        "likely_severity": "Critical",
                        "permissionless_action": "Admin sets unsafe config.",
                        "attacker_control": "partial",
                        "rubric_row": "Protocol insolvency",
                        "dupe_risk": "low",
                    },
                ]
            }), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--exploit-queue",
                    str(queue),
                    "--workspace",
                    str(root),
                    "--top-n",
                    "2",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            aggregate = root / ".auditooor" / "prefiling_stress_test.json"
            self.assertTrue(aggregate.is_file())
            payload = json.loads(aggregate.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["pass"], 1)
            self.assertEqual(payload["summary"]["fail"], 1)

    def test_cli_skips_terminal_rows_before_top_n_selection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            queue = root / "exploit_queue.json"
            queue.write_text(json.dumps({
                "queue": [
                    {
                        "lead_id": "EQ-KILLED",
                        "title": "Killed high candidate",
                        "likely_severity": "High",
                        "proof_status": "killed",
                        "quality_gate_status": "closed_negative_operator_review",
                        "learning_route": "drop",
                    },
                    {
                        "lead_id": "EQ-CLEAN",
                        "title": "Public withdraw drains vault user funds",
                        "likely_severity": "High",
                        "permissionless_action": "Unprivileged attacker calls withdraw(shareAmount).",
                        "attacker_control": "known",
                        "rubric_row": "Direct theft of any user funds",
                        "dupe_risk": "low",
                        "proof_path": "foundry",
                    },
                ]
            }), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--exploit-queue",
                    str(queue),
                    "--workspace",
                    str(root),
                    "--top-n",
                    "1",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            payload = json.loads((root / ".auditooor" / "prefiling_stress_test.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["terminal_rows_skipped"], 1)
            self.assertEqual(payload["rows_assessed"], 1)
            self.assertEqual(payload["results"][0]["candidate_id"], "EQ-CLEAN")

    def test_cli_skips_explicit_non_proof_rows_before_top_n_selection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            queue = root / "exploit_queue.json"
            queue.write_text(json.dumps({
                "queue": [
                    {
                        "lead_id": "EQ-COVERAGE",
                        "title": "Corpus coverage row, not a proof candidate",
                        "likely_severity": "High",
                        "proof_status": "open",
                        "proof_relevance": False,
                        "proof_relevance_status": "skipped_non_proof",
                    },
                    {
                        "lead_id": "EQ-CLEAN",
                        "title": "Public withdraw drains vault user funds",
                        "likely_severity": "High",
                        "permissionless_action": "Unprivileged attacker calls withdraw(shareAmount).",
                        "attacker_control": "known",
                        "rubric_row": "Direct theft of any user funds",
                        "dupe_risk": "low",
                        "proof_path": "foundry",
                    },
                ]
            }), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--exploit-queue", str(queue), "--workspace", str(root), "--top-n", "1"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            payload = json.loads((root / ".auditooor" / "prefiling_stress_test.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["non_proof_rows_skipped"], 0)
            self.assertEqual(payload["unresolved_non_proof_rows"], 1)
            self.assertEqual(payload["rows_assessed"], 1)
            self.assertEqual(payload["results"][0]["candidate_id"], "EQ-CLEAN")

    def test_strict_fails_when_top_n_truncates_proof_eligible_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            queue = root / "exploit_queue.json"
            base = {
                "title": "Public withdraw drains vault user funds",
                "likely_severity": "High",
                "permissionless_action": "Unprivileged attacker calls withdraw(shareAmount).",
                "attacker_control": "known",
                "rubric_row": "Direct theft of any user funds",
                "dupe_risk": "low",
                "proof_path": "foundry",
            }
            queue.write_text(json.dumps({
                "queue": [
                    {"lead_id": "EQ-CLEAN-1", **base},
                    {"lead_id": "EQ-CLEAN-2", **base},
                ]
            }), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--exploit-queue", str(queue), "--workspace", str(root), "--top-n", "1", "--strict"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr + proc.stdout)
            payload = json.loads((root / ".auditooor" / "prefiling_stress_test.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["proof_eligible_rows_total"], 2)
            self.assertEqual(payload["proof_eligible_rows_unassessed"], 1)
            self.assertIn("proof_eligible_rows_truncated", payload["strict_blockers"])

    def test_strict_fails_when_only_non_proof_rows_remain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            queue = root / "exploit_queue.json"
            queue.write_text(json.dumps({
                "queue": [{
                    "lead_id": "EQ-COVERAGE",
                    "title": "Corpus coverage row, not a proof candidate",
                    "proof_status": "open",
                    "proof_relevance": False,
                    "proof_relevance_status": "skipped_non_proof",
                }]
            }), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--exploit-queue", str(queue), "--workspace", str(root), "--strict"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr + proc.stdout)
            payload = json.loads((root / ".auditooor" / "prefiling_stress_test.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["strict_blockers"], ["unresolved_non_proof_rows"])

    def test_strict_allows_terminal_and_non_proof_rows_without_open_proof_work(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            queue = root / "exploit_queue.json"
            queue.write_text(json.dumps({
                "queue": [
                    {
                        "lead_id": "EQ-CLOSED",
                        "title": "Previously adjudicated candidate",
                        "status": "closed_negative",
                    },
                    {
                        "lead_id": "EQ-COVERAGE",
                        "title": "Corpus coverage row, not a proof candidate",
                        "proof_status": "open",
                        "proof_relevance": False,
                        "proof_relevance_status": "skipped_non_proof",
                    },
                ]
            }), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--exploit-queue", str(queue),
                 "--workspace", str(root), "--strict"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            payload = json.loads((root / ".auditooor" / "prefiling_stress_test.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["terminal_rows_skipped"], 1)
            self.assertEqual(payload["non_proof_rows_skipped"], 1)
            self.assertEqual(payload["rows_assessed"], 0)


class PrefilingOutcomeLessonAdoptionTest(unittest.TestCase):
    """HACKERMAN_V3 Lane J5a: shared outcome-lesson classifier as pre-PoC fails."""

    def _clean_high_row(self, extra_text: str) -> dict:
        # A row that is otherwise clean (permissionless, rubric, dupe-clean,
        # compatible proof) so the only fail driver is the shared classifier.
        return {
            "lead_id": "EQ-J5A",
            "title": "Public withdraw drains vault user funds",
            "likely_severity": "High",
            "permissionless_action": "Unprivileged attacker calls withdraw(shareAmount) on VaultRouter.",
            "attacker_control": "known",
            "selected_impact": "Direct theft of user funds",
            "rubric_row": "Direct theft of any user funds, whether at-rest or in-motion",
            "dupe_risk": "low",
            "proof_path": "foundry",
            "source_refs": ["contracts/VaultRouter.sol:120"],
            "raw_draft_text": extra_text,
        }

    def test_result_carries_outcome_lesson_gate_field(self) -> None:
        result = tool.assess(self._clean_high_row("A clean unprivileged path."), "candidate_row")
        self.assertIn("outcome_lesson_gate", result)
        self.assertTrue(result["outcome_lesson_gate"]["available"])

    def test_documented_mechanics_predicate_routes_pre_poc_fail(self) -> None:
        # Revert #102 documented-mechanics-not-intent: the shared classifier's
        # documented_mechanics_no_stronger_intent hard predicate becomes a
        # pre-PoC scope fail.
        result = tool.assess(
            self._clean_high_row(
                "The behavior is exactly the documented mechanics; docs say the fee "
                "accrues this way and there is no stronger design intent than the "
                "documented behavior."
            ),
            "candidate_row",
        )
        self.assertEqual(result["verdict"], "fail")
        self.assertIn(
            "outcome_lesson_documented_mechanics_no_stronger_intent",
            result["scope_blockers"],
        )
        self.assertIn(
            "outcome_lesson_documented_mechanics_no_stronger_intent",
            result["blocked_reasons"],
        )

    def test_low_severity_cap_predicate_routes_pre_poc_fail(self) -> None:
        # Revert #991/#995 low caps: low_severity_cap_triggered hard predicate.
        result = tool.assess(
            self._clean_high_row(
                "Impact is dust only with no material loss; severity is capped at "
                "low and the finding should be downgraded to informational."
            ),
            "candidate_row",
        )
        self.assertEqual(result["verdict"], "fail")
        self.assertIn(
            "outcome_lesson_low_severity_cap_triggered",
            result["scope_blockers"],
        )

    def test_mev_but_protocol_bug_is_not_a_pre_poc_hard_fail(self) -> None:
        # Revert #15 MEV-but-protocol-bug: protocol_bug_amplified_by_mev is an
        # advisory predicate, not a hard one, so it must NOT route a fail.
        result = tool.assess(
            self._clean_high_row(
                "The contract has a root cause: a missing slippage check allows the "
                "swap to fail. MEV amplifies the loss for the victim, but the "
                "protocol fault exists first."
            ),
            "candidate_row",
        )
        self.assertNotIn(
            "outcome_lesson_protocol_bug_amplified_by_mev",
            result["blocked_reasons"],
        )
        self.assertNotIn(
            "outcome_lesson_ambient_mev_not_protocol_bug",
            result["blocked_reasons"],
        )

    def test_bank_fundaccount_seed_is_not_synthetic_state_dependency(self) -> None:
        # nuva begin-blocker DoS (2026-07-04): the cosmos-sdk x/bank `FundAccount`
        # test-seed helper performs a real MintCoins + SendCoinsFromModuleToAccount
        # bank deposit (used in 15 of provlabs/vault's own keeper tests). It is the
        # standard production-faithful way to seed balances and must NOT be
        # mis-classified as a synthetic/privileged/mock dependency.
        result = tool.assess(
            self._clean_high_row(
                "PoC seed (real bank deposit, the standard SimApp helper): "
                "require.NoError(t, FundAccount(ctx, app.BankKeeper, vaultAddr, "
                "sdk.NewCoins(sdk.NewInt64Coin(underlyingDenom, 1_000_000_000))))"
            ),
            "candidate_row",
        )
        self.assertNotIn(
            "privileged_mock_oos_or_synthetic_dependency_present",
            result["blocked_reasons"],
        )
        # The false-positive also drove the admin_or_team_action_prerequisite
        # scope predicate via `bool(flags or admin_pause_prereq)`; that must clear too.
        self.assertNotIn(
            "outcome_lesson_admin_or_team_action_prerequisite",
            result.get("scope_blockers", []),
        )

    def test_genuine_synthetic_state_injection_still_flags(self) -> None:
        # Guard against over-broadening: real synthetic-state injection
        # (reflection / unsafe.pointer / direct db key write) MUST still flag.
        result = tool.assess(
            self._clean_high_row(
                "PoC seeds the flood via reflection and unsafe.Pointer writes "
                "directly into the store (direct db key injection), bypassing the "
                "message path entirely."
            ),
            "candidate_row",
        )
        self.assertIn(
            "privileged_mock_oos_or_synthetic_dependency_present",
            result["blocked_reasons"],
        )


if __name__ == "__main__":
    unittest.main()
