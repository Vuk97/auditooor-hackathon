from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "v3-source-first-row-gate.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("v3_source_first_row_gate", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load v3-source-first-row-gate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class V3SourceFirstRowGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="v3-source-first-row-gate-")
        self.ws = Path(self.tmp.name)
        (self.ws / ".auditooor").mkdir()
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_json(self, rel: str, payload: dict) -> None:
        path = self.ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def write_scope_target(
        self,
        *,
        pin: str = "a" * 40,
        language: str | None = "rust",
        owner_repo: str = "polytope-labs/hyperbridge",
        key: str = "targets",
        bare: bool = False,
    ) -> None:
        target = {
            "repo_url": owner_repo if bare else f"https://github.com/{owner_repo}",
            "pin": pin,
            "local_name": owner_repo.rsplit("/", 1)[-1],
        }
        if language is not None:
            target["language"] = language
        self.write_json("scope.json", {key: [target]})

    def write_commit_mining_evidence(
        self,
        *,
        owner_repo: str = "polytope-labs/hyperbridge",
        pin: str = "a" * 40,
        language: str = "rust",
        status: str = "ok",
        commits_scanned: int = 8,
        report_pin: str | None = None,
        include_report_pin: bool = True,
        report_exists: bool = True,
        summary_failed: int = 0,
        suffix: str = "rust",
    ) -> None:
        report_rel = f"mining_rounds/2026-05-21-bidirectional-commit-mining/{owner_repo.replace('/', '_')}_{suffix}_git_commits_mining.json"
        if report_exists:
            report = {
                "schema": "auditooor.git_commits_mining.v1",
                "upstream_repo": owner_repo,
                "commits_scanned": commits_scanned,
                "generated_at": "2026-05-21T00:00:00Z",
                "shaped_commits_index": [
                    {
                        "sha": pin,
                        "url": f"https://github.com/{owner_repo}/commit/{pin}",
                        "subject": "fix: bounded source-first mining fixture",
                    }
                ],
            }
            if include_report_pin:
                report["audit_pin_sha"] = report_pin if report_pin is not None else pin
            self.write_json(report_rel, report)
        self.write_json(
            ".auditooor/commit_lifecycle_ledger.json",
            {
                "schema": "auditooor.commit_lifecycle_ledger.v1",
                "audit_pin_sha": pin,
                "forward_window": {"count": commits_scanned},
                "backward_window": {"count": 90},
                "target_rows": [
                    {
                        "owner_repo": owner_repo,
                        "pin": pin,
                        "language": language,
                        "status": status,
                        "commits_scanned": commits_scanned,
                        "output_path": report_rel,
                    }
                ],
                "summary": {
                    "targets_seen": 1,
                    "rows": 1,
                    "commits_scanned": commits_scanned,
                    "failed": summary_failed,
                },
            },
        )

    def write_clean_artifacts(self) -> None:
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-001",
                        "title": "source-mined bridge payout replay",
                        "likely_severity": "critical",
                        "source_artifacts_complete": True,
                        "truth_table_complete": True,
                        "source_refs": ["runtime/src/bridge.rs:120"],
                        "source_artifacts": ["source_artifacts/EQ-001.json"],
                        "reachability_trace": (
                            "Reachability trace: dispatched via production bridge router at "
                            "runtime/src/bridge.rs:120 under default config"
                        ),
                        "impact_contract_status": "mapped",
                        "oos_traps": ["not front-run-only; source-only bounty"],
                        "negative_control": (
                            "same payload with consumed nonce must fail; "
                            "defender wins: nonce replay guard rejects the payload; "
                            "defender absent: with the nonce replay guard removed the replay drains funds"
                        ),
                        "next_command": "cargo test -p pallet-ismp test_bridge_replay -- --nocapture",
                    }
                ],
            },
        )
        self.write_json(
            ".auditooor/impact_contracts.json",
            {
                "schema": "auditooor.impact_contracts.v1",
                "contracts": [
                    {
                        "impact_contract_id": "IC-001",
                        "candidate_id": "EQ-001",
                        "status": "locked",
                        "selected_impact": "Stealing or loss of funds",
                        "exact_impact_row": True,
                        "attacker_actor": "permissionless relayer",
                        "victim_actor": "bridge user",
                        "asset_at_risk": "escrowed bridge funds",
                        "dispatch_site": "runtime/src/bridge.rs:120",
                        "oos_traps": ["not imported-contract-only"],
                        "negative_control": (
                            "valid already-processed message is rejected; "
                            "defender wins: nonce replay guard catches the replay; "
                            "defender absent: with the guard removed the replay succeeds"
                        ),
                        "protocol_defenses_enumerated": ["nonce replay guard"],
                        "opposed_trace_required": True,
                        "opposed_trace_coverage": "covered",
                        "missing_defenses": [],
                    }
                ],
            },
        )
        self.write_json(
            ".auditooor/prove_top_leads_candidate_judgment_packet.json",
            {
                "schema": "auditooor.candidate_judgment_packet.v1",
                "packets": [
                    {
                        "packet_id": "CJP-001",
                        "candidate_id": "EQ-001",
                        "packet_state": "ready_for_poc_planning",
                        "promotion_blockers": [],
                    }
                ],
            },
        )
        self.write_json(
            ".auditooor/harness_execution_queue_from_exploit_queue.json",
            {
                "schema": "auditooor.harness_execution_queue.v0",
                "rows": [
                    {
                        "row_id": "EQ-001",
                        "title": "source-mined bridge payout replay",
                        "status": "ready_executable_binding",
                        "blockers": [],
                    }
                ],
            },
        )

    def test_passes_when_source_first_contract_is_complete(self) -> None:
        self.write_clean_artifacts()
        gate = self.tool.build_gate(self.ws)
        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["summary"]["rows_considered"], 1)
        self.assertEqual(gate["rows"][0]["blockers"], [])
        self.assertEqual(gate["rows"][0]["reachability_status"], "ready")
        self.assertEqual(
            gate["artifacts"]["commit_mining"]["status"],
            "advisory_no_pinned_github_targets",
        )

    def test_non_terminal_duplicate_review_status_is_not_skipped(self) -> None:
        self.write_clean_artifacts()
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8")
        )
        queue["queue"][0]["status"] = "not_duplicate_checked"
        self.write_json(".auditooor/exploit_queue.source_mined.json", queue)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["summary"]["rows_considered"], 1)
        self.assertEqual(gate["summary"]["rows_skipped"], 0)
        self.assertEqual(gate["rows"][0]["lead_id"], "EQ-001")

    def test_non_terminal_advisory_review_status_is_not_skipped(self) -> None:
        self.write_clean_artifacts()
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8")
        )
        queue["queue"][0]["quality_gate_status"] = "needs_advisory_review"
        self.write_json(".auditooor/exploit_queue.source_mined.json", queue)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["summary"]["rows_considered"], 1)
        self.assertEqual(gate["summary"]["rows_skipped"], 0)
        self.assertEqual(gate["rows"][0]["lead_id"], "EQ-001")

    def test_terminal_duplicate_status_is_skipped(self) -> None:
        self.write_clean_artifacts()
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8")
        )
        queue["queue"][0]["status"] = "duplicate"
        self.write_json(".auditooor/exploit_queue.source_mined.json", queue)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["summary"]["rows_considered"], 0)
        self.assertEqual(gate["summary"]["rows_skipped"], 1)

    def test_prior_audit_dupe_artifact_failure_blocks_medium_plus_row(self) -> None:
        self.write_clean_artifacts()
        self.write_json(
            ".auditooor/source_first_prior_audit_dupe_gate.json",
            {
                "schema": "auditooor.prior_audit_dupe_gate.v1",
                "mode": "queue",
                "verdict_summary": "fail",
                "gate_pass": False,
                "prior_audit_count": 1,
                "drafts": [
                    {
                        "lead_id": "EQ-001",
                        "candidate_id": "EQ-001",
                        "verdict": "likely-dupe",
                        "gate_pass": False,
                        "reason": "Queue row has likely-dupe adjacency with prior audit.",
                    }
                ],
            },
        )

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertIn("prior_audit_dupe:likely-dupe", gate["rows"][0]["blockers"])
        self.assertIn("prior_audit_dupe:likely-dupe", gate["summary"]["blocker_counts"])
        self.assertEqual(gate["rows"][0]["prior_audit_dupe"]["verdict"], "likely-dupe")

    def test_prior_audit_dupe_artifact_clear_allows_medium_plus_row(self) -> None:
        self.write_clean_artifacts()
        self.write_json(
            ".auditooor/source_first_prior_audit_dupe_gate.json",
            {
                "schema": "auditooor.prior_audit_dupe_gate.v1",
                "mode": "queue",
                "verdict_summary": "pass",
                "gate_pass": True,
                "prior_audit_count": 1,
                "drafts": [
                    {
                        "lead_id": "EQ-001",
                        "candidate_id": "EQ-001",
                        "verdict": "clear",
                        "gate_pass": True,
                        "reason": "No prior-audit component overlap detected.",
                    }
                ],
            },
        )

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertNotIn("prior_audit_dupe:clear", gate["rows"][0]["blockers"])
        self.assertEqual(gate["artifacts"]["prior_audit_dupe"]["rows"], 1)

    def test_prior_audit_dupe_artifact_no_prior_audits_is_not_blocking(self) -> None:
        self.write_clean_artifacts()
        self.write_json(
            ".auditooor/source_first_prior_audit_dupe_gate.json",
            {
                "schema": "auditooor.prior_audit_dupe_gate.v1",
                "mode": "queue",
                "verdict_summary": "no-prior-audits",
                "gate_pass": True,
                "prior_audit_count": 0,
                "drafts": [],
            },
        )

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["rows"][0]["prior_audit_dupe"]["status"], "no_prior_audits")

    def test_reachability_trace_required_for_medium_plus(self) -> None:
        self.write_clean_artifacts()
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8")
        )
        queue["queue"][0]["likely_severity"] = "medium"
        queue["queue"][0].pop("reachability_trace")
        self.write_json(".auditooor/exploit_queue.source_mined.json", queue)
        contracts = json.loads((self.ws / ".auditooor" / "impact_contracts.json").read_text(encoding="utf-8"))
        contracts["contracts"][0].pop("dispatch_site")
        self.write_json(".auditooor/impact_contracts.json", contracts)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertEqual(gate["rows"][0]["reachability_status"], "missing")
        self.assertIn("reachability_missing_trace", gate["rows"][0]["blockers"])
        self.assertIn("reachability_missing_trace", gate["summary"]["blocker_counts"])

    def test_reachability_trace_can_come_from_impact_contract(self) -> None:
        self.write_clean_artifacts()
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8")
        )
        queue["queue"][0].pop("reachability_trace")
        self.write_json(".auditooor/exploit_queue.source_mined.json", queue)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["rows"][0]["reachability_status"], "ready")
        self.assertNotIn("reachability_missing_trace", gate["rows"][0]["blockers"])

    def test_reachability_unreachable_blocks_medium_plus(self) -> None:
        self.write_clean_artifacts()
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8")
        )
        queue["queue"][0]["likely_severity"] = "medium"
        queue["queue"][0]["reachability_trace"] = (
            "Reachability trace: code is present but unreachable; it is never dispatched "
            "in production under default config. Override site runtime/src/bridge.rs:120"
        )
        self.write_json(".auditooor/exploit_queue.source_mined.json", queue)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertEqual(gate["rows"][0]["reachability_status"], "unreachable")
        self.assertIn("reachability_unreachable", gate["rows"][0]["blockers"])

    def test_reachability_not_required_for_low_row(self) -> None:
        self.write_clean_artifacts()
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8")
        )
        queue["queue"][0]["likely_severity"] = "low"
        queue["queue"][0].pop("reachability_trace")
        self.write_json(".auditooor/exploit_queue.source_mined.json", queue)
        contracts = json.loads((self.ws / ".auditooor" / "impact_contracts.json").read_text(encoding="utf-8"))
        contracts["contracts"][0].pop("dispatch_site")
        self.write_json(".auditooor/impact_contracts.json", contracts)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["rows"][0]["reachability_status"], "not_required")
        self.assertNotIn("reachability_missing_trace", gate["rows"][0]["blockers"])

    def test_weak_reachability_rebuttal_with_generic_source_refs_still_blocks_medium_plus(self) -> None:
        self.write_clean_artifacts()
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8")
        )
        queue["queue"][0]["likely_severity"] = "medium"
        queue["queue"][0].pop("reachability_trace")
        queue["queue"][0]["reachability_rebuttal"] = "manual review pending"
        self.write_json(".auditooor/exploit_queue.source_mined.json", queue)
        contracts = json.loads((self.ws / ".auditooor" / "impact_contracts.json").read_text(encoding="utf-8"))
        contracts["contracts"][0].pop("dispatch_site")
        self.write_json(".auditooor/impact_contracts.json", contracts)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertEqual(gate["rows"][0]["reachability_status"], "missing")
        self.assertIn("reachability_missing_trace", gate["rows"][0]["blockers"])

    def test_source_backed_typed_reachability_exception_can_satisfy_medium_plus(self) -> None:
        self.write_clean_artifacts()
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.source_mined.json").read_text(encoding="utf-8")
        )
        queue["queue"][0]["likely_severity"] = "medium"
        queue["queue"][0].pop("reachability_trace")
        queue["queue"][0]["reachability_exception"] = (
            "source-backed exception: dispatch not required because production registration "
            "is constructor-only at runtime/src/bridge.rs:120"
        )
        self.write_json(".auditooor/exploit_queue.source_mined.json", queue)
        contracts = json.loads((self.ws / ".auditooor" / "impact_contracts.json").read_text(encoding="utf-8"))
        contracts["contracts"][0].pop("dispatch_site")
        self.write_json(".auditooor/impact_contracts.json", contracts)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["rows"][0]["reachability_status"], "ready")

    # ------------------------------------------------------------------
    # HACKERMAN_V3 opposed-trace proof gate (POINT 2)
    # ------------------------------------------------------------------
    def _high_plus_row(self) -> dict:
        return {
            "lead_id": "EQ-OPP",
            "title": "watcher accepts unrelated exit - direct loss of funds",
            "likely_severity": "critical",
            "source_artifacts_complete": True,
            "source_refs": ["runtime/src/watch_chain.rs:842"],
            "source_artifacts": ["source_artifacts/EQ-OPP.json"],
            "reachability_trace": (
                "Reachability trace: dispatched from the production exit router at "
                "runtime/src/watch_chain.rs:842 under default config"
            ),
            "impact_contract_status": "mapped",
            "oos_traps": ["not imported-library-only"],
            "negative_control": "consumed exit txid must be rejected",
            "next_command": "cargo test -p watcher test_exit_replay -- --nocapture",
        }

    def _opposed_contract(self, **over) -> dict:
        contract = {
            "impact_contract_id": "IC-OPP",
            "candidate_id": "EQ-OPP",
            "status": "mapped",
            "selected_impact": "Direct loss of user funds",
            "exact_impact_row": True,
            "attacker_actor": "permissionless relayer",
            "victim_actor": "exiting user",
            "asset_at_risk": "escrowed user funds",
            "dispatch_site": "runtime/src/watch_chain.rs:842",
            "oos_traps": ["not imported-library-only"],
            "negative_control": (
                "consumed exit txid is rejected; "
                "defender wins: lower-timelock refund recovers the funds; "
                "defender absent: with the refund path removed the attacker drains funds"
            ),
            "protocol_defenses_enumerated": ["lower-timelock connector refund", "watchtower path"],
            "opposed_trace_required": True,
            "opposed_trace_coverage": "covered",
            "missing_defenses": [],
        }
        contract.update(over)
        return contract

    def test_opposed_trace_empty_defenses_fails_closed(self) -> None:
        # HIGH+ row, contract with empty enumerated defenses -> typed blocker.
        result = self.tool.evaluate_row(
            self._high_plus_row(),
            impact_contract=self._opposed_contract(
                protocol_defenses_enumerated=[],
                opposed_trace_coverage="missing",
                missing_defenses=[],
            ),
            judgment_packet={"packet_state": "ready_for_poc_planning", "promotion_blockers": []},
            harness_row={"status": "ready_executable_binding", "blockers": []},
        )
        self.assertEqual(result["status"], "fail")
        self.assertIn("unopposed_trace_high_plus", result["blockers"])

    def test_opposed_trace_required_but_coverage_not_covered_fails_closed(self) -> None:
        # HIGH+ row, opposed_trace_required + coverage=missing -> typed blocker.
        result = self.tool.evaluate_row(
            self._high_plus_row(),
            impact_contract=self._opposed_contract(
                opposed_trace_coverage="missing",
                missing_defenses=["watchtower path"],
            ),
            judgment_packet={"packet_state": "ready_for_poc_planning", "promotion_blockers": []},
            harness_row={"status": "ready_executable_binding", "blockers": []},
        )
        self.assertEqual(result["status"], "fail")
        self.assertIn("unopposed_trace_high_plus", result["blockers"])

    def test_opposed_trace_missing_defender_control_variants_fail_closed(self) -> None:
        # HIGH+ row, defenses enumerated + covered, but negative controls have
        # neither a defender-wins nor a defender-absent variant -> both typed
        # control blockers fire.
        row = self._high_plus_row()
        row["negative_control"] = "consumed exit txid must be rejected"
        result = self.tool.evaluate_row(
            row,
            impact_contract=self._opposed_contract(
                negative_control="consumed exit txid is rejected"
            ),
            judgment_packet={"packet_state": "ready_for_poc_planning", "promotion_blockers": []},
            harness_row={"status": "ready_executable_binding", "blockers": []},
        )
        self.assertEqual(result["status"], "fail")
        self.assertIn("opposed_trace_missing_defender_wins_control", result["blockers"])
        self.assertIn("opposed_trace_missing_defender_absent_control", result["blockers"])

    def test_opposed_trace_fully_covered_passes(self) -> None:
        # HIGH+ row with enumerated + covered defenses and both control
        # variants -> no opposed-trace blocker.
        result = self.tool.evaluate_row(
            self._high_plus_row(),
            impact_contract=self._opposed_contract(),
            judgment_packet={"packet_state": "ready_for_poc_planning", "promotion_blockers": []},
            harness_row={"status": "ready_executable_binding", "blockers": []},
        )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["blockers"], [])

    def test_opposed_trace_not_applied_to_non_high_plus_row(self) -> None:
        # A low-severity, non-fund-loss row is not subject to the opposed-trace
        # gate even with an empty-defenses contract.
        row = self._high_plus_row()
        row["likely_severity"] = "low"
        row["title"] = "minor event ordering quirk"
        result = self.tool.evaluate_row(
            row,
            impact_contract={
                "impact_contract_id": "IC-LOW",
                "candidate_id": "EQ-OPP",
                "status": "mapped",
                "selected_impact": "Event emitted in wrong order",
                "exact_impact_row": True,
                "attacker_actor": "permissionless caller",
                "victim_actor": "indexer",
                "asset_at_risk": "indexer event stream",
                "oos_traps": ["not cosmetic-only"],
                "negative_control": "removing the bug leaves event order unchanged",
            },
            judgment_packet={"packet_state": "ready_for_poc_planning", "promotion_blockers": []},
            harness_row={"status": "ready_executable_binding", "blockers": []},
        )
        self.assertNotIn("unopposed_trace_high_plus", result["blockers"])
        self.assertEqual(result["status"], "pass")

    def test_opposed_trace_advisory_on_non_high_plus_freeze_row(self) -> None:
        # Tiered model: a non-HIGH+ (Medium) freeze-class row with an
        # unopposed-trace impact contract gets an advisory_unopposed_trace
        # WARNING (non-blocking) - the row still passes the gate, but the
        # missing opposed trace stays visible to the reviewer.
        row = self._high_plus_row()
        row["likely_severity"] = "medium"
        row["title"] = "temporary freeze of user funds during dispute window"
        result = self.tool.evaluate_row(
            row,
            impact_contract={
                "impact_contract_id": "IC-MED",
                "candidate_id": "EQ-OPP",
                "status": "mapped",
                "selected_impact": "Temporary freezing of user funds",
                "exact_impact_row": True,
                "attacker_actor": "permissionless caller",
                "victim_actor": "depositor",
                "asset_at_risk": "deposited funds",
                "oos_traps": ["not cosmetic-only"],
                "negative_control": "removing the bug unfreezes funds",
                "protocol_defenses_enumerated": [],
                "opposed_trace_coverage": "missing",
                "contract_advisories": ["opposed_trace_defenses_unenumerated"],
            },
            judgment_packet={"packet_state": "ready_for_poc_planning", "promotion_blockers": []},
            harness_row={"status": "ready_executable_binding", "blockers": []},
        )
        # Advisory, not a blocker - the row still passes.
        self.assertNotIn("unopposed_trace_high_plus", result["blockers"])
        self.assertIn("advisory_unopposed_trace", result["warnings"])
        self.assertEqual(result["status"], "pass")

    def test_build_gate_fails_closed_on_unopposed_high_plus_row(self) -> None:
        # End-to-end: a HIGH+ row whose impact contract has no opposed-trace
        # coverage makes the whole gate fail with the typed blocker counted.
        self.write_clean_artifacts()
        self.write_json(
            ".auditooor/impact_contracts.json",
            {
                "schema": "auditooor.impact_contracts.v1",
                "contracts": [self._opposed_contract(
                    impact_contract_id="IC-001",
                    candidate_id="EQ-001",
                    protocol_defenses_enumerated=[],
                    opposed_trace_coverage="missing",
                )],
            },
        )
        gate = self.tool.build_gate(self.ws)
        self.assertEqual(gate["status"], "fail")
        self.assertIn("unopposed_trace_high_plus", gate["summary"]["blocker_counts"])

    def test_commit_mining_passes_with_matching_pinned_github_target(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target()
        self.write_commit_mining_evidence()

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["rows"][0]["blockers"], [])
        self.assertEqual(gate["artifacts"]["commit_mining"]["status"], "pass")
        self.assertEqual(gate["artifacts"]["commit_mining"]["pinned_github_targets"], 1)
        self.assertEqual(gate["artifacts"]["commit_mining"]["matching_target_rows"], 1)

    def test_commit_mining_missing_for_pinned_github_target_fails(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target()

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertNotIn("commit_mining_missing", gate["rows"][0]["blockers"])
        self.assertIn("commit_mining_missing", gate["summary"]["global_blockers"])
        self.assertIn("commit_mining_missing", gate["artifacts"]["commit_mining"]["blockers"])

    def test_commit_mining_missing_is_global_blocker_without_active_rows(self) -> None:
        self.write_scope_target()

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertEqual(gate["summary"]["rows_considered"], 0)
        self.assertIn("commit_mining_missing", gate["summary"]["global_blockers"])

    def test_commit_mining_pin_mismatch_fails(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target(pin="a" * 40)
        self.write_commit_mining_evidence(pin="b" * 40, report_pin="b" * 40)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertIn("commit_mining_pin_mismatch", gate["summary"]["global_blockers"])

    def test_commit_mining_parses_target_repos_and_bare_owner_repo(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target(key="target_repos", bare=True, language=None)
        self.write_commit_mining_evidence(language="")

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["artifacts"]["commit_mining"]["pinned_github_targets"], 1)
        self.assertEqual(gate["artifacts"]["commit_mining"]["matching_target_rows"], 1)

    def test_commit_mining_accepts_targets_tsv_bare_owner_repo(self) -> None:
        self.write_clean_artifacts()
        (self.ws / "targets.tsv").write_text(
            f"polytope-labs/hyperbridge\t{'a' * 40}\thyperbridge\trust\n",
            encoding="utf-8",
        )
        self.write_commit_mining_evidence()

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["artifacts"]["commit_mining"]["pinned_github_targets"], 1)

    def test_commit_mining_accepts_targets_tsv_one_column_inline_pin(self) -> None:
        self.write_clean_artifacts()
        (self.ws / "targets.tsv").write_text(
            f"polytope-labs/hyperbridge@{'a' * 40}\n",
            encoding="utf-8",
        )
        self.write_commit_mining_evidence(language="")

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["artifacts"]["commit_mining"]["pinned_github_targets"], 1)

    def test_commit_mining_rejects_scope_string_target_with_non_40_global_ref(self) -> None:
        self.write_clean_artifacts()
        self.write_json(
            "scope.json",
            {"target_repos": ["polytope-labs/hyperbridge"], "audit_pin_sha": "main"},
        )

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertIn("commit_mining_pin_mismatch", gate["summary"]["global_blockers"])
        self.assertEqual(gate["artifacts"]["commit_mining"]["pinned_github_targets"], 1)
        self.assertEqual(
            gate["artifacts"]["commit_mining"]["invalid_pin_targets"][0]["pin"],
            "main",
        )

    def test_commit_mining_rejects_bare_owner_repo_targets_tsv_non_40_ref(self) -> None:
        self.write_clean_artifacts()
        (self.ws / "targets.tsv").write_text(
            "polytope-labs/hyperbridge\tmain\thyperbridge\trust\n",
            encoding="utf-8",
        )

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertIn("commit_mining_pin_mismatch", gate["summary"]["global_blockers"])
        self.assertEqual(gate["artifacts"]["commit_mining"]["pinned_github_targets"], 1)

    def test_commit_mining_rejects_failed_dry_run_empty_and_missing_report(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target(language=None)
        report_rel = "mining_rounds/2026-05-21-bidirectional-commit-mining/polytope-labs_hyperbridge_ok_git_commits_mining.json"
        self.write_json(
            report_rel,
            {
                "schema": "auditooor.git_commits_mining.v1",
                "upstream_repo": "polytope-labs/hyperbridge",
                "audit_pin_sha": "a" * 40,
                "commits_scanned": 0,
                "generated_at": "2026-05-21T00:00:00Z",
                "shaped_commits_index": [
                    {"sha": "a" * 40, "url": f"https://github.com/polytope-labs/hyperbridge/commit/{'a' * 40}"}
                ],
            },
        )
        self.write_json(
            ".auditooor/commit_lifecycle_ledger.json",
            {
                "schema": "auditooor.commit_lifecycle_ledger.v1",
                "target_rows": [
                    {
                        "owner_repo": "polytope-labs/hyperbridge",
                        "pin": "a" * 40,
                        "language": "rust",
                        "status": "failed",
                        "commits_scanned": 5,
                        "output_path": report_rel,
                    },
                    {
                        "owner_repo": "polytope-labs/hyperbridge",
                        "pin": "a" * 40,
                        "language": "solidity",
                        "status": "dry_run",
                        "commits_scanned": 5,
                        "output_path": report_rel,
                    },
                    {
                        "owner_repo": "polytope-labs/hyperbridge",
                        "pin": "a" * 40,
                        "language": "go",
                        "status": "ok",
                        "commits_scanned": 0,
                        "output_path": "mining_rounds/missing-report.json",
                    },
                ],
                "summary": {"failed": 1},
            },
        )

        gate = self.tool.build_gate(self.ws)
        blockers = set(gate["rows"][0]["blockers"])

        self.assertEqual(gate["status"], "fail")
        global_blockers = set(gate["summary"]["global_blockers"])
        self.assertNotIn("commit_mining_failed", blockers)
        self.assertIn("commit_mining_failed", global_blockers)
        self.assertIn("commit_mining_empty", global_blockers)
        self.assertIn("commit_mining_missing", global_blockers)

    def test_commit_mining_requires_40_hex_pin_for_github_targets(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target(pin="main")

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertIn("commit_mining_pin_mismatch", gate["summary"]["global_blockers"])

    def test_commit_mining_rejects_report_without_audit_pin(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target()
        self.write_commit_mining_evidence(include_report_pin=False)

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertIn("commit_mining_pin_mismatch", gate["summary"]["global_blockers"])

    def test_commit_mining_rejects_fake_report_with_matching_pin_and_count(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target()
        report_rel = "mining_rounds/2026-05-21-bidirectional-commit-mining/fake_git_commits_mining.json"
        self.write_json(
            report_rel,
            {
                "schema": "auditooor.git_commits_mining.v1",
                "upstream_repo": "polytope-labs/hyperbridge",
                "audit_pin_sha": "a" * 40,
                "commits_scanned": 8,
                "generated_at": "2026-05-21T00:00:00Z",
                "head_sha": "x",
            },
        )
        self.write_json(
            ".auditooor/commit_lifecycle_ledger.json",
            {
                "schema": "auditooor.commit_lifecycle_ledger.v1",
                "target_rows": [
                    {
                        "owner_repo": "polytope-labs/hyperbridge",
                        "pin": "a" * 40,
                        "language": "rust",
                        "status": "ok",
                        "commits_scanned": 8,
                        "output_path": report_rel,
                    }
                ],
            },
        )

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertIn(
            "commit_mining_report_lacks_commit_evidence",
            gate["summary"]["global_blockers"],
        )

    def test_commit_mining_accepts_canonical_empty_window_report(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target()
        report_rel = "mining_rounds/2026-05-21-bidirectional-commit-mining/empty_git_commits_mining.json"
        self.write_json(
            report_rel,
            {
                "schema": "auditooor.git_commits_mining.v1",
                "schema_version": "1.1",
                "workspace": str(self.ws),
                "upstream_repo": "polytope-labs/hyperbridge",
                "audit_pin_sha": "a" * 40,
                "since_date": "2026-05-21",
                "generated_at": "2026-05-21T00:00:00Z",
                "commits_scanned": 0,
                "security_fix_count": 0,
                "filter_regex": "fix|security",
                "fallback_used": False,
                "commits": [],
                "shaped_commits_index": [],
            },
        )
        self.write_json(
            ".auditooor/commit_lifecycle_ledger.json",
            {
                "schema": "auditooor.commit_lifecycle_ledger.v1",
                "target_rows": [
                    {
                        "owner_repo": "polytope-labs/hyperbridge",
                        "pin": "a" * 40,
                        "language": "rust",
                        "status": "ok",
                        "commits_scanned": 0,
                        "output_path": report_rel,
                    }
                ],
            },
        )

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["artifacts"]["commit_mining"]["status"], "pass")

    def test_markdown_labels_commit_mining_global_blockers_separately(self) -> None:
        self.write_scope_target()

        gate = self.tool.build_gate(self.ws)
        markdown = self.tool.render_md(gate)

        self.assertIn("## Global Blockers", markdown)
        self.assertIn("`commit_mining_missing`", markdown)

    def test_commit_mining_language_mismatch_is_explicit(self) -> None:
        self.write_clean_artifacts()
        self.write_scope_target(language="rust")
        self.write_commit_mining_evidence(language="solidity")

        gate = self.tool.build_gate(self.ws)

        self.assertEqual(gate["status"], "fail")
        self.assertIn("commit_mining_language_mismatch", gate["summary"]["global_blockers"])

    def test_cli_print_json_matches_written_sidecar(self) -> None:
        self.write_clean_artifacts()
        out_json = self.ws / ".auditooor" / "row_gate_custom.json"
        out_md = self.ws / ".auditooor" / "row_gate_custom.md"

        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(self.ws),
                "--out-json",
                str(out_json),
                "--out-md",
                str(out_md),
                "--print-json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), json.loads(out_json.read_text(encoding="utf-8")))

    def test_fails_high_plus_row_with_missing_contracts_and_controls(self) -> None:
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-002",
                        "title": "source-mined candidate without proof contract",
                        "likely_severity": "high",
                        "source_artifacts_complete": False,
                        "impact_contract_status": "unknown",
                        "next_command": "# build a harness later",
                    }
                ],
            },
        )
        self.write_json(
            ".auditooor/harness_execution_queue_from_exploit_queue.json",
            {
                "schema": "auditooor.harness_execution_queue.v0",
                "rows": [
                    {
                        "row_id": "EQ-002",
                        "status": "blocked_missing_inputs",
                        "blockers": ["missing_command", "missing_gating_test"],
                    }
                ],
            },
        )

        gate = self.tool.build_gate(self.ws)
        blockers = set(gate["rows"][0]["blockers"])
        self.assertEqual(gate["status"], "fail")
        self.assertIn("source_artifacts_incomplete", blockers)
        self.assertIn("proof_command_is_comment", blockers)
        self.assertIn("missing_impact_contract", blockers)
        self.assertIn("missing_oos_traps", blockers)
        self.assertIn("missing_negative_control", blockers)
        self.assertIn("missing_candidate_judgment_packet", blockers)
        self.assertIn("harness_missing_command", blockers)

    def test_skips_terminal_or_advisory_rows(self) -> None:
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-003",
                        "title": "killed candidate",
                        "proof_status": "killed",
                        "quality_gate_status": "killed",
                    }
                ],
            },
        )
        gate = self.tool.build_gate(self.ws)
        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["summary"]["rows_considered"], 0)
        self.assertEqual(gate["summary"]["rows_skipped"], 1)

    def test_needs_source_rows_are_considered_not_skipped(self) -> None:
        self.write_json(
            ".auditooor/exploit_queue.source_mined.json",
            {
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-004",
                        "title": "needs-source candidate",
                        "likely_severity": "critical",
                        "quality_gate_status": "needs_source",
                        "proof_status": "needs_source",
                    }
                ],
            },
        )
        gate = self.tool.build_gate(self.ws)
        self.assertEqual(gate["status"], "fail")
        self.assertEqual(gate["summary"]["rows_considered"], 1)
        self.assertEqual(gate["summary"]["rows_skipped"], 0)
        self.assertIn("source_artifacts_incomplete", gate["rows"][0]["blockers"])

    def test_generated_unvalidated_impact_contract_does_not_pass_row_gate(self) -> None:
        self.write_clean_artifacts()
        contracts = json.loads((self.ws / ".auditooor" / "impact_contracts.json").read_text(encoding="utf-8"))
        contracts["contracts"][0]["status"] = "generated_unvalidated"
        contracts["contracts"][0]["impact_contract_status"] = "generated_unvalidated"
        contracts["contracts"][0]["listed_impact_proven"] = False
        self.write_json(".auditooor/impact_contracts.json", contracts)

        gate = self.tool.build_gate(self.ws)
        self.assertEqual(gate["status"], "fail")
        self.assertIn(
            "impact_contract_status:generated_unvalidated",
            gate["rows"][0]["blockers"],
        )


if __name__ == "__main__":
    unittest.main()
