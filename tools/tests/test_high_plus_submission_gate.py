"""Regression coverage for the bounded HIGH+ submission gate wrapper."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "high-plus-submission-gate.py"
MCP = ROOT / "tools" / "vault-mcp-server.py"


class HighPlusSubmissionGateTest(unittest.TestCase):
    def test_high_live_claim_blocks_missing_selected_impact_and_target_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Live topology issue leads to fund freeze

                    **Severity:** High

                    The proof depends on live topology and TARGET_PROTOCOL.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            payload = json.loads(proc.stdout)
            codes = {row["code"] for row in payload["blockers"]}
            self.assertIn("PRODUCTION_REACHABILITY_MISSING", codes)
            self.assertIn("selected_impact_missing_or_placeholder", codes)
            self.assertIn("target_protocol_live_hardening_missing", codes)
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_same_block_lab_harness_is_not_live_topology_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # ABCI overflow leads to permanent freezing of funds

                    **Severity:** Critical

                    ## Impact Contract
                    - selected_impact: Permanent freezing of funds
                    - severity_tier: Critical
                    - listed_impact_proven: true
                    - opposed_trace_coverage: not_applicable

                    ## Production Reachability
                    - production_reachability: production-profile-lab-path

                    Four independent validators fail on the same block in a
                    production-profile FinalizeBlock integration harness.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["live_hardening"]["live_claim_detected"])
            self.assertNotIn(
                "target_protocol_live_hardening_missing",
                {row["code"] for row in payload["blockers"]},
            )

    def test_source_only_live_proof_na_is_not_live_topology_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # ABCI overflow leads to permanent freezing of funds

                    **Severity:** Critical

                    ## Impact Contract
                    - selected_impact: Permanent freezing of funds
                    - severity_tier: Critical
                    - listed_impact_proven: true
                    - opposed_trace_coverage: not_applicable

                    ## Production Reachability
                    - production_reachability: production-profile-lab-path.
                      The harness exercises the same code a mainnet validator
                      runs every block.

                    This finding is source-only: live-proof evidence: n/a.
                    No live mainnet deployment-state read is required.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["live_hardening"]["live_claim_detected"])
            self.assertNotIn(
                "target_protocol_live_hardening_missing",
                {row["code"] for row in payload["blockers"]},
            )

    def test_high_blocks_missing_production_reachability_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Accounting bug leads to direct theft

                    **Severity:** High

                    ## Impact Contract
                    - Victim: LPs
                    - selected_impact: Direct theft of user funds
                    - severity_tier: High
                    - listed_impact_proven: true
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertIn("PRODUCTION_REACHABILITY_MISSING", {row["code"] for row in payload["blockers"]})
            self.assertFalse(payload["live_hardening"]["production_reachability_declared"])

    def test_high_role_access_control_blocks_without_live_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Access control deployment-state mismatch freezes withdrawals

                    **Severity:** High

                    ## Impact Contract
                    - selected_impact: Permanent freezing of user funds
                    - severity_tier: High
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed withdrawal adapter is used by users.

                    The withdrawal adapter depends on an access control permission that
                    the deployment-state setup does not grant.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertIn(
                "case_study_role_live_enumeration_missing",
                {row["code"] for row in payload["blockers"]},
            )
            self.assertTrue(payload["case_study_enforcement"]["role_or_deployment_claim_detected"])
            self.assertFalse(payload["case_study_enforcement"]["live_enumeration_evidence_present"])
            self.assertTrue(payload["case_study_obligations"])

    def test_high_role_access_control_passes_with_live_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Access control deployment-state mismatch freezes withdrawals

                    **Severity:** High

                    ## Impact Contract
                    - selected_impact: Permanent freezing of user funds
                    - severity_tier: High
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed withdrawal adapter is used by users.

                    The withdrawal adapter depends on an access control permission that
                    the deployment-state setup does not grant.

                    Evidence: cast call confirms on-chain enumeration
                    for the adapter and shows the missing permission.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertNotIn(
                "case_study_role_live_enumeration_missing",
                {row["code"] for row in payload["blockers"]},
            )
            self.assertTrue(payload["case_study_enforcement"]["live_enumeration_evidence_present"])

    def test_high_plus_warns_on_triager_rejection_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Event-only drafting artifact

                    **Severity:** High

                    ## Impact Contract
                    - Victim: users
                    - selected_impact: Direct theft of user funds
                    - severity_tier: High
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed route reachable by unprivileged user.

                    This issue is only cosmetic and only affects event emission with no
                    functional impact.

                    <!-- opposed-trace-rebuttal: test fixture for triager-rejection-language check only -->
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            warning_codes = {row["code"] for row in payload["warnings"]}
            self.assertIn("triager_pattern_match", warning_codes)
            self.assertEqual(payload["status"], "pass")
            self.assertIn("triager_pattern_matches", payload)
            self.assertGreaterEqual(len(payload["triager_pattern_matches"]), 1)
            self.assertLessEqual(len(payload["triager_pattern_matches"]), 4)

    def test_high_plus_includes_severity_calibration_advisory_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Accounting bug has unclear impact axis

                    **Severity:** High

                    ## Impact Contract
                    - Victim: LPs
                    - selected_impact: Unauthorized accounting drift
                    - severity_tier: High
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed Vault route is reachable by an unprivileged LP.
                    - role enumeration: cast call rolesOf confirms the unprivileged LP route does not require an admin role.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "pass")
            self.assertEqual(payload["submission_posture"], "SUBMIT_GATE_PASSED")
            self.assertEqual(payload["severity_calibration_gate"]["verdict"], "pass-with-advisory")
            self.assertIn("high_claim_missing_concrete_impact_axis", payload["severity_calibration_gate"]["advisory"])
            self.assertIn("severity_calibration_advisory", {row["code"] for row in payload["warnings"]})
            self.assertEqual(payload["severity_calibration_gate"]["impact_kind"], "unknown")

    def test_critical_protocol_yield_overclaim_blocks_via_severity_calibration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Protocol fee residual can be swept

                    **Severity:** Critical

                    ## Impact Contract
                    - Victim: protocol treasury
                    - selected_impact: Theft of protocol yield and accumulated fees
                    - severity_tier: Critical
                    - listed_impact_proven: true

                    ## Production Reachability
                    - production path: deployed fee sweeper route is reachable by an unprivileged caller.

                    The attacker can sweep accumulated fees from protocol yield.
                    assertGt(attackerBalanceAfter, attackerBalanceBefore);
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            payload = json.loads(proc.stdout)
            blocker_codes = {row["code"] for row in payload["blockers"]}
            self.assertIn(
                "severity_calibration_critical_claim_maps_to_protocol_yield_theft_not_user_fund_theft",
                blocker_codes,
            )
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(payload["severity_calibration_gate"]["verdict"], "fail-severity-overclaim")
            self.assertEqual(payload["severity_calibration_gate"]["predicted_triager_tier"], "high")

    def test_mcp_callable_surfaces_triager_pattern_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Event-only drafting artifact

                    **Severity:** Critical

                    ## Impact Contract
                    - Victim: users
                    - selected_impact: Direct theft of user funds
                    - severity_tier: Critical
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed route reachable by unprivileged user.

                    This issue is only cosmetic and only affects event emission with no
                    functional impact.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            args = json.dumps(
                {
                    "draft_path": str(draft),
                    "workspace_path": tmp,
                    "severity": "Critical",
                    "run_pre_submit": False,
                }
            )
            proc = subprocess.run(
                [sys.executable, str(MCP), "--call", "vault_high_plus_submission_gate", "--args", args],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], "auditooor.vault_high_plus_submission_gate.v1")
            warning_codes = {row["code"] for row in payload["warnings"]}
            self.assertIn("triager_pattern_match", warning_codes)
            self.assertIn("reference/triager_patterns.json", payload["source_refs"])
            self.assertEqual(len(payload["triager_pattern_matches"]), 1)
            self.assertIn("R", payload["triager_pattern_matches"][0]["pattern_id"])
            self.assertIn("severity_calibration_gate", payload)
            self.assertIn("tools/severity-calibration-gate.py", payload["source_refs"])

    def test_high_reachability_section_does_not_accept_negated_phrase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Accounting bug leads to direct theft

                    **Severity:** High

                    ## Impact Contract
                    - selected_impact: Direct theft of user funds
                    - severity_tier: High
                    - listed_impact_proven: true

                    ## Production Reachability
                    - production reachability: not a live production path; lab only.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertIn("PRODUCTION_REACHABILITY_MISSING", {row["code"] for row in payload["blockers"]})
            self.assertFalse(payload["live_hardening"]["production_reachability_declared"])

    def test_bridge_release_claim_blocks_missing_response_path_or_release_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Bridge quorum bypass leads to unauthorized release

                    **Severity:** High

                    ## Impact Contract
                    - selected_impact: Direct theft of user funds
                    - severity_tier: High
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed bridge adapter accepts destination packets.

                    The bridge receive library reaches quorum with one attestation and releases
                    locked inventory to the attacker.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertIn(
                "bridge_response_or_release_proof_missing",
                {row["code"] for row in payload["blockers"]},
            )
            self.assertTrue(payload["live_hardening"]["bridge_release_or_quorum_claim_detected"])
            self.assertFalse(payload["live_hardening"]["bridge_response_or_release_proof_present"])

    def test_bridge_release_claim_accepts_explicit_response_path_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Bridge quorum bypass leads to unauthorized release

                    **Severity:** High

                    ## Impact Contract
                    - selected_impact: Direct theft of user funds
                    - severity_tier: High
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed bridge adapter accepts destination packets.

                    The bridge receive library reaches quorum with one attestation and releases
                    locked inventory to the attacker.

                    - response-path: source packet -> lzReceive -> adapter release call is covered by PoC assertions.

                    <!-- opposed-trace-rebuttal: test fixture for bridge-response-path-proof check only -->
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertNotIn(
                "bridge_response_or_release_proof_missing",
                {row["code"] for row in payload["blockers"]},
            )
            self.assertTrue(payload["live_hardening"]["bridge_release_or_quorum_claim_detected"])
            self.assertTrue(payload["live_hardening"]["bridge_response_or_release_proof_present"])

    def test_critical_bridge_cross_contract_invariant_blocks_without_smt_and_fuzz(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Bridge cross-contract invariant bypass releases funds

                    **Severity:** Critical

                    ## Impact Contract
                    - selected_impact: Direct theft of user funds
                    - severity_tier: Critical
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed bridge finalization route is permissionless.

                    The bridge cross-contract invariant between verifier and portal can be
                    violated during withdrawal finalization.

                    - response-path: source packet -> verifier -> portal release call is covered by PoC assertions.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertIn(
                "case_study_bridge_invariant_smt_and_fuzz_missing",
                {row["code"] for row in payload["blockers"]},
            )
            enforcement = payload["case_study_enforcement"]
            self.assertTrue(enforcement["bridge_cross_contract_invariant_claim_detected"])
            self.assertFalse(enforcement["symbolic_or_smt_evidence_present"])
            self.assertFalse(enforcement["fuzz_or_reachability_evidence_present"])

    def test_critical_bridge_cross_contract_invariant_passes_with_smt_and_fuzz(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Bridge cross-contract invariant bypass releases funds

                    **Severity:** Critical

                    ## Impact Contract
                    - selected_impact: Direct theft of user funds
                    - severity_tier: Critical
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed bridge finalization route is permissionless.

                    The bridge cross-contract invariant between verifier and portal can be
                    violated during withdrawal finalization.

                    Evidence combines a Halmos SMT counter-example proving the predicate
                    admits the bad state with forge fuzz permissionless reachability showing
                    the bridge release path is reachable.

                    - response-path: source packet -> verifier -> portal release call is covered by PoC assertions.

                    <!-- opposed-trace-rebuttal: test fixture for bridge-invariant-smt-and-fuzz check only -->
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertNotIn(
                "case_study_bridge_invariant_smt_and_fuzz_missing",
                {row["code"] for row in payload["blockers"]},
            )
            enforcement = payload["case_study_enforcement"]
            self.assertTrue(enforcement["symbolic_or_smt_evidence_present"])
            self.assertTrue(enforcement["fuzz_or_reachability_evidence_present"])

    def test_non_bridge_release_wording_does_not_trigger_bridge_proof_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bypass leads to unauthorized release

                    **Severity:** High

                    ## Impact Contract
                    - selected_impact: Direct theft of user funds
                    - severity_tier: High
                    - listed_impact_proven: true

                    ## Production Reachability
                    - live production path: deployed vault release function is reachable by an unprivileged LP.

                    The vault can release funds after the accounting bypass.

                    <!-- opposed-trace-rebuttal: no protocol rescue path for this vault asset class; test fixture -->
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertNotIn(
                "bridge_response_or_release_proof_missing",
                {row["code"] for row in payload["blockers"]},
            )
            self.assertFalse(payload["live_hardening"]["bridge_release_or_quorum_claim_detected"])

    def test_mcp_callable_exposes_single_draft_gate_without_pre_submit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Accounting bug leads to direct theft

                    **Severity:** High

                    ## Impact Contract
                    - Victim: LPs
                    - Source proof: src/Vault.sol:10
                    - selected_impact: Direct theft of user funds
                    - severity_tier: High
                    - listed_impact_proven: true
                    - evidence_class: forge_test
                    - oos_traps: admin path excluded
                    - stop_condition: stop if theft assertion no longer holds

                    ## Production Reachability
                    - live production path: deployed Vault route is reachable by an unprivileged LP.

                    <!-- opposed-trace-rebuttal: test fixture for MCP callable check only -->
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            args = json.dumps(
                {
                    "draft_path": str(draft),
                    "workspace_path": tmp,
                    "severity": "High",
                    "run_pre_submit": False,
                }
            )
            proc = subprocess.run(
                [sys.executable, str(MCP), "--call", "vault_high_plus_submission_gate", "--args", args],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], "auditooor.vault_high_plus_submission_gate.v1")
            self.assertEqual(payload["status"], "pass")
            self.assertEqual(payload["blockers"], [])
            self.assertIn("vault_high_plus_submission_gate", {tool["name"] for tool in self._tool_list()})

    def _tool_list(self) -> list[dict]:
        proc = subprocess.run(
            [sys.executable, str(MCP), "--self-test"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        import importlib.util

        spec = importlib.util.spec_from_file_location("vault_mcp_server_for_gate_test", MCP)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module.TOOL_SCHEMAS


class OpposedTraceGateBlockerTest(unittest.TestCase):
    """Verify the HACKERMAN_V3 unopposed_trace_for_direct_loss blocker in the high-plus gate."""

    def _run_gate(self, body: str, filename: str = "draft-HIGH.md") -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / filename
            draft.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            payload = json.loads(proc.stdout)
            payload["_returncode"] = proc.returncode
            return payload

    def test_direct_loss_no_defense_blocks_with_unopposed_trace(self) -> None:
        """AT-1 mirror: High Direct Loss with no defense signals -> unopposed_trace_for_direct_loss."""
        payload = self._run_gate(
            """
            # Chain-watcher gap leads to direct loss of funds

            - Severity: High

            ## Impact Contract
            - selected_impact: Direct loss of funds
            - severity_tier: High
            - listed_impact_proven: true
            - evidence_class: executed_poc
            - oos_traps: []
            - stop_condition: do_not_claim_critical

            ## Production Reachability
            - production_reachability: production-profile-lab-path

            The attacker submits a forged txid. The watcher confirms it.
            Funds are permanently lost. No protocol defense is mentioned.
            """
        )
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn(
            "unopposed_trace_for_direct_loss",
            codes,
            f"Expected unopposed_trace_for_direct_loss blocker; got: {codes}",
        )
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_direct_loss_with_defense_and_attacker_wins_passes(self) -> None:
        """AT-3 mirror: Defense enumerated and attacker wins -> no unopposed_trace blocker."""
        payload = self._run_gate(
            """
            # Chain-watcher gap leads to direct loss of funds

            - Severity: High

            ## Impact Contract
            - selected_impact: Direct loss of funds
            - severity_tier: High
            - listed_impact_proven: true
            - evidence_class: executed_poc
            - oos_traps: []
            - stop_condition: do_not_claim_critical

            ## Production Reachability
            - production_reachability: production-profile-lab-path

            ## Protocol-Owned Defenses Considered

            | Defense | Code path | Expected protection | Included in PoC? | Result |
            |---|---|---|---|---|
            | Watchtower | watchtower/sweep.go:44 | Detect forged txid | Yes | Defense fails: attacker wins |

            Outcome: attacker wins despite the watchtower defense.
            Funds are permanently lost.
            """
        )
        codes = {row["code"] for row in payload["blockers"]}
        self.assertNotIn(
            "unopposed_trace_for_direct_loss",
            codes,
            f"Unexpected opposed-trace blocker with defense+attacker-wins; blockers: {codes}",
        )

    def test_direct_loss_rebuttal_bypasses_blocker(self) -> None:
        """A valid opposed-trace-rebuttal marker suppresses the blocker."""
        payload = self._run_gate(
            """
            # Missing guard leads to direct loss of funds

            - Severity: High

            ## Impact Contract
            - selected_impact: Direct loss of funds
            - severity_tier: High
            - listed_impact_proven: true
            - evidence_class: executed_poc
            - oos_traps: []
            - stop_condition: do_not_claim_critical

            ## Production Reachability
            - production_reachability: production-profile-lab-path

            No protocol defense exists for this asset class.

            <!-- opposed-trace-rebuttal: no watchtower/refund path exists for user-EOA asset; confirmed by SCOPE.md:14 -->
            """
        )
        codes = {row["code"] for row in payload["blockers"]}
        self.assertNotIn(
            "unopposed_trace_for_direct_loss",
            codes,
            f"Expected rebuttal to suppress opposed-trace blocker; blockers: {codes}",
        )

    def test_opposed_trace_gate_in_payload(self) -> None:
        """The high-plus payload must include an opposed_trace_gate field."""
        payload = self._run_gate(
            """
            # Example leads to direct loss of funds

            - Severity: High

            ## Impact Contract
            - selected_impact: Direct loss of funds
            - listed_impact_proven: true

            ## Production Reachability
            - production_reachability: production-profile-lab-path
            """
        )
        self.assertIn("opposed_trace_gate", payload, "opposed_trace_gate field missing from payload")


class HighPlusOutcomeLessonAdoptionTest(unittest.TestCase):
    """HACKERMAN_V3 Lane J5a: shared outcome-lesson classifier as High+ blockers."""

    def _run_gate(self, body: str, filename: str = "draft-HIGH.md") -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / filename
            draft.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            payload = json.loads(proc.stdout)
            payload["_returncode"] = proc.returncode
            return payload

    def test_payload_carries_outcome_lesson_gate_field(self) -> None:
        payload = self._run_gate(
            """
            # Clean finding leads to direct loss of funds

            - Severity: High

            ## Impact Contract
            - selected_impact: Direct loss of funds
            - listed_impact_proven: true

            ## Production Reachability
            - production_reachability: production-profile-lab-path
            """
        )
        self.assertIn("outcome_lesson_gate", payload)
        self.assertIn("tools/outcome-lesson-gate.py", payload["source_refs"])

    def test_polymarket_198_economics_predicate_becomes_blocker(self) -> None:
        # Polymarket #198 economics: value-extraction claim with no attacker
        # profit / unprofitable path -> economic_viability_missing hard predicate.
        payload = self._run_gate(
            """
            # Polymarket reward extraction leads to direct loss of funds

            - Severity: High

            ## Impact Contract
            - selected_impact: Direct loss of funds
            - listed_impact_proven: true

            ## Production Reachability
            - production_reachability: production-profile-lab-path

            The attacker extracts the creator reward, but there is no attacker
            profit once gas is accounted for; the path is unprofitable under
            realistic execution costs.
            """
        )
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn("outcome_lesson_economic_viability_missing", codes)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["_returncode"], 1)

    def test_documented_mechanics_not_intent_becomes_blocker(self) -> None:
        payload = self._run_gate(
            """
            # Documented fee skim leads to direct loss of funds

            - Severity: High

            ## Impact Contract
            - selected_impact: Direct loss of funds
            - listed_impact_proven: true

            ## Production Reachability
            - production_reachability: production-profile-lab-path

            The behavior is exactly the documented mechanics; docs say the fee
            accrues this way and there is no stronger design intent than the
            documented behavior.
            """
        )
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn("outcome_lesson_documented_mechanics_no_stronger_intent", codes)


class BridgeReleaseQuorumClaimTest(unittest.TestCase):
    """Rank-6(b): the bridge release/quorum obligation must require a real bridge
    primitive and must be suppressed in refutation/disclaimer context, while
    still firing on a genuine bridge release/quorum claim."""

    @staticmethod
    def _gate_module():
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "high_plus_submission_gate_for_bridge_test", TOOL
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module

    def test_genuine_bridge_release_claim_still_fires(self):
        # Control / true-positive: real primitive (LayerZero/DVN) + release/quorum.
        mod = self._gate_module()
        text = (
            "The LayerZero bridge releases the escrow once the DVN quorum "
            "attestation is finalized on the destination chain."
        )
        self.assertTrue(mod._has_bridge_release_or_quorum_claim(text))

    def test_disclaimed_bridge_context_suppressed(self):
        # False-positive suppressed: refutation/contrast phrasing.
        mod = self._gate_module()
        text = (
            "This is not a bridge finding; there is no cross-chain release path, "
            "so no quorum or attestation is required for the impact."
        )
        self.assertFalse(mod._has_bridge_release_or_quorum_claim(text))

    def test_generic_tokens_without_primitive_suppressed(self):
        # False-positive suppressed: generic "validator-set" + "withdrawal"
        # with no real bridge primitive is a single-chain finding.
        mod = self._gate_module()
        text = (
            "A validator-set rotation lets an operator trigger an early "
            "withdrawal from the single-chain staking pool."
        )
        self.assertFalse(mod._has_bridge_release_or_quorum_claim(text))

    def _griefing_dos_draft_body(self) -> str:
        # A no-profit griefing DoS High draft that DISCUSSES economics / admin /
        # MEV only to rule them out (attacker gains nothing, unprivileged path,
        # protocol fault not ambient MEV). The shared outcome-lesson classifier's
        # draft-text predicates are not reliably negation-aware and can hard-fail
        # such a draft (economic_viability_missing / ambient_mev_not_protocol_bug /
        # admin_or_team_action_prerequisite). nuva begin-blocker DoS, 2026-07-04.
        return textwrap.dedent(
            """
            # Unbounded consensus-hook walk leads to Temporary freezing of funds

            **Severity:** High

            ## Impact Contract
            - Victim: honest redeemers
            - selected_impact: Temporary freezing of funds
            - severity_tier: High
            - listed_impact_proven: true

            ## Production Reachability
            - live production path: BeginBlocker runs every block on every validator; unprivileged MsgCreateVault reaches it.

            ## Impact
            This is a NO-PROFIT griefing DoS: the attacker gains nothing, burns gas,
            and is frozen too. profit_or_loss_statement: attacker net PnL is a LOSS.
            It is a protocol fault (missing per-block cap), NOT ambient MEV / sandwich /
            front-run. The path is permissionless: MsgCreateVault has no admin, owner,
            governance, or team gate.
            """
        ).strip() + "\n"

    def test_outcome_lesson_false_red_blocks_high_plus_griefing_dos_without_rebuttal(self) -> None:
        import os
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(self._griefing_dos_draft_body(), encoding="utf-8")
            env = dict(os.environ)
            env["TARGET_PROTOCOL"] = "provenance-mainnet:pio-mainnet-1"
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json", "--severity", "high"],
                cwd=ROOT, text=True, capture_output=True, check=False, env=env,
            )
            payload = json.loads(proc.stdout)
            blocker_codes = {row["code"] for row in payload["blockers"]}
            self.assertTrue(
                any(c.startswith("outcome_lesson_") and not c.endswith("_rebutted") for c in blocker_codes),
                f"expected an outcome_lesson hard blocker, got {blocker_codes}",
            )

    def test_outcome_lesson_rebuttal_marker_converts_blocker_to_warning(self) -> None:
        import os
        body = self._griefing_dos_draft_body() + (
            "\n<!-- outcome-lesson-rebuttal: economic_viability_missing: no-profit griefing; "
            "attacker net PnL is a LOSS, impact=availability not value-extraction -->\n"
            "<!-- outcome-lesson-rebuttal: ambient_mev_not_protocol_bug: protocol fault "
            "(missing per-block cap on consensus hook), deterministic, not mempool ordering -->\n"
            "<!-- outcome-lesson-rebuttal: admin_or_team_action_prerequisite: MsgCreateVault "
            "is permissionless with no admin/authority gate (source-cited) -->\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(body, encoding="utf-8")
            env = dict(os.environ)
            env["TARGET_PROTOCOL"] = "provenance-mainnet:pio-mainnet-1"
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(draft), "--skip-pre-submit", "--json", "--severity", "high"],
                cwd=ROOT, text=True, capture_output=True, check=False, env=env,
            )
            payload = json.loads(proc.stdout)
            blocker_codes = {row["code"] for row in payload["blockers"]}
            warning_codes = {row["code"] for row in payload["warnings"]}
            self.assertFalse(
                any(c.startswith("outcome_lesson_") and not c.endswith("_rebutted") for c in blocker_codes),
                f"outcome_lesson blockers should be rebutted, got {blocker_codes}",
            )
            self.assertTrue(
                any(c.endswith("_rebutted") for c in warning_codes),
                f"expected rebutted warnings, got {warning_codes}",
            )


if __name__ == "__main__":
    unittest.main()
