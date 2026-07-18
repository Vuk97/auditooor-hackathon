from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

_spec = importlib.util.spec_from_file_location(
    "triager_pre_filing_simulator",
    REPO_ROOT / "tools" / "triager-pre-filing-simulator.py",
)
_sim = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
assert _spec.loader is not None
_spec.loader.exec_module(_sim)


class TriagerPrecheckFixtureTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ws = self.root / "workspace"
        self.ws.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _draft(self, body: str, name: str = "draft.md") -> Path:
        path = self.ws / name
        path.write_text(body, encoding="utf-8")
        return path

    def _packet(self, body: str, name: str = "draft.md") -> dict:
        return _sim.build_precheck(self._draft(body, name=name), self.ws)

    def _ids(self, packet: dict) -> set[str]:
        return {str(row.get("id")) for row in packet["matched_patterns"]}

    def _silent(self, packet: dict, key: str) -> dict:
        rows = packet["silent_kill_predictions"]
        self.assertEqual(
            {row["class_key"] for row in rows},
            {
                "duplicate",
                "no_fund_impact",
                "dos",
                "design_intended",
                "event_only",
                "user_error",
                "reachability",
            },
        )
        return next(row for row in rows if row["class_key"] == key)

    def test_event_only_matches_r1(self) -> None:
        packet = self._packet(
            """# Wrong event topic

Severity: High

The issue only affects event emission. There is no functional impact and the
underlying mapping remains correct.
"""
        )
        self.assertEqual(packet["schema"], "auditooor.triager_precheck_rules.v1")
        self.assertEqual(packet["mode"], "rules_mvp")
        self.assertEqual(packet["silent_kill_summary"]["mind_model_version"], "p4-local-mind-model-v1")
        self.assertGreaterEqual(packet["silent_kill_summary"]["covered_taste_questions"], 7)
        self.assertTrue(packet["mind_model_checks"])
        self.assertEqual(packet["local_rules_status"]["state"], "completed")
        self.assertFalse(packet["local_rules_status"]["provider_backed"])
        self.assertFalse(packet["local_rules_status"]["provider_call_made"])
        self.assertTrue(packet["local_rules_status"]["silent_kill_predictions_supported"])
        self.assertIn(packet["provider_status"]["state"], {"not_configured", "configured", "blocked"})
        self.assertIsInstance(packet["provider_status"]["provider"], str)
        self.assertFalse(packet["provider_status"]["provider_backed"])
        self.assertFalse(packet["provider_status"]["provider_call_made"])
        self.assertEqual(packet["provider_status"]["simulation_scope"], "deterministic_local_rules_only")
        self.assertFalse(packet["provider_status"]["predicted_verdict_supported"])
        self.assertIsNone(packet["predicted_verdict"])
        self.assertEqual(
            packet["capability_boundary"],
            {
                "local_rules_mvp": True,
                "provider_dispatch": False,
                "provider_backed_simulation": False,
                "predicted_triager_verdict": False,
                "triager_verdict_or_clearance": False,
            },
        )
        self.assertIn("R1", self._ids(packet))
        self.assertGreater(packet["class_votes"]["F_no_fund_impact_or_actor_model"], 0)
        self.assertEqual(packet["disposition_evidence"]["source"], "local_disposition_classifier")
        self.assertFalse(packet["disposition_evidence"]["provider_backed"])
        self.assertEqual(packet["disposition_evidence"]["predicted_provider_verdict"], None)
        self.assertEqual(
            packet["disposition_evidence"]["disposition"],
            "needs_non_self_impact_or_actor_model",
        )
        self.assertIn("reference/triager_disposition_classifier.json", packet["source_refs"])
        self.assertEqual(
            packet["recommended_action"],
            "strengthen_non_self_impact_or_actor_model_before_filing",
        )
        event_only = self._silent(packet, "event_only")
        self.assertTrue(event_only["matched"])
        self.assertEqual(event_only["prediction"], "silent_kill_predicted")
        self.assertIn("only affects event emission", event_only["evidence_phrases"])
        self.assertTrue(event_only["suggested_strengthening"])
        self.assertIn("event_or_cosmetic_only", event_only["mind_model_check_ids"])
        self.assertEqual(event_only["mind_model_status"]["event_or_cosmetic_only"], "risk")
        no_fund = self._silent(packet, "no_fund_impact")
        self.assertTrue(no_fund["matched"])
        self.assertIn("no functional impact", no_fund["evidence_phrases"])
        self.assertEqual(packet["silent_kill_summary"]["top_class"], "event_only")

    def test_event_signal_with_downstream_value_movement_rebuts_event_only_kill(self) -> None:
        packet = self._packet(
            """# Wrong event feeds payout accounting

Severity: High

The contract emits a wrong event, but the event is consumed by downstream
accounting and causes a downstream functional failure. The attacker can steal
from a non-self victim and the PoC records a balance delta.
"""
        )

        event_only = self._silent(packet, "event_only")
        self.assertFalse(event_only["matched"])
        self.assertEqual(event_only["prediction"], "not_predicted")
        self.assertIn("downstream functional failure", event_only["rebuttal_phrases"])
        self.assertIn("event_only", packet["silent_kill_summary"]["risk_classes_rebutted"])
        checks = {row["check_id"]: row for row in packet["mind_model_checks"]}
        self.assertEqual(checks["event_or_cosmetic_only"]["status"], "risk_rebutted")
        self.assertEqual(checks["non_self_value_movement"]["status"], "rebuttal_present")

    def test_extreme_value_matches_r2(self) -> None:
        packet = self._packet(
            """# Packed maker amount overflow

Severity: High

This depends on makerAmount > 2^248. Theoretical extreme value overflow is the
core trigger, and no realistic scenario reaches that supply.
"""
        )
        self.assertIn("R2", self._ids(packet))
        self.assertGreater(packet["class_votes"]["F_prime_reachability_realism"], 0)
        self.assertEqual(
            packet["recommended_action"],
            "justify_realistic_reachability_before_filing",
        )
        reachability = self._silent(packet, "reachability")
        self.assertTrue(reachability["matched"])
        self.assertIn("no realistic scenario", reachability["evidence_phrases"])
        self.assertTrue(reachability["suggested_strengthening"])

    def test_reachability_proof_rebuts_unrealistic_precondition_kill(self) -> None:
        packet = self._packet(
            """# Edge state reached through a normal entrypoint

Severity: Medium

The edge condition is theoretical in isolation, but the fork test drives a
normal entrypoint with a permissionless trigger and shows the production path
that creates the bad state.
"""
        )

        reachability = self._silent(packet, "reachability")
        self.assertFalse(reachability["matched"])
        self.assertIn("fork test", reachability["rebuttal_phrases"])
        self.assertIn("reachability", packet["silent_kill_summary"]["risk_classes_rebutted"])
        checks = {row["check_id"]: row for row in packet["mind_model_checks"]}
        self.assertEqual(checks["realistic_reachability"]["status"], "risk_rebutted")

    def test_actor_model_user_error_matches_r17(self) -> None:
        packet = self._packet(
            """# Receiver relies on sender supplied txid

Severity: Critical

The sender says the receiver must verify the unrelated txid. A reviewer may
call this user error or counterparty risk unless the actor table proves the
victim is not the attacker.
"""
        )
        self.assertIn("R17", self._ids(packet))
        self.assertGreater(packet["class_votes"]["F_no_fund_impact_or_actor_model"], 0)
        user_error = self._silent(packet, "user_error")
        self.assertTrue(user_error["matched"])
        self.assertIn("user error", user_error["evidence_phrases"])
        self.assertIn("actor table", user_error["suggested_strengthening"])

    def test_design_intended_silent_kill_prediction(self) -> None:
        packet = self._packet(
            """# Pause domains do not cascade

Severity: Medium

The behavior is acknowledged as by design and expected behavior. This is an
architectural domain separation choice unless we prove value extraction.
"""
        )
        design = self._silent(packet, "design_intended")
        self.assertTrue(design["matched"])
        self.assertIn("by design", design["evidence_phrases"])
        self.assertIn("strictly stronger", design["suggested_strengthening"])
        self.assertFalse(self._silent(packet, "user_error")["matched"])

    def test_generic_dos_silent_kill_prediction_without_provider_claim(self) -> None:
        packet = self._packet(
            """# Localized RPC DoS

Severity: High

This is a generic DoS caused by rate-limit pressure on localized CheckTx and
RPC pressure. It has no matching-engine or chain-liveness degradation.
"""
        )
        dos = self._silent(packet, "dos")
        self.assertTrue(dos["matched"])
        self.assertFalse(dos["provider_backed"])
        self.assertFalse(packet["capability_boundary"]["provider_backed_simulation"])
        self.assertIn("generic dos", dos["evidence_phrases"])
        self.assertIn("production entrypoint", dos["suggested_strengthening"])
        self.assertEqual(dos["mind_model_status"]["production_grade_evidence"], "risk")

    def test_duplicateish_workspace_overlap_matches_r9(self) -> None:
        submissions = self.ws / "submissions" / "staging"
        submissions.mkdir(parents=True)
        (submissions / "prior.md").write_text(
            "# Collateral offramp unwrap missing wrapper role\n\nOlder draft.",
            encoding="utf-8",
        )
        packet = self._packet(
            "# Collateral offramp unwrap missing wrapper role\n\nNew wording of same root cause.",
            name="new.md",
        )
        self.assertIn("R9", self._ids(packet))
        self.assertTrue(any(w["code"] == "workspace_duplicateish_overlap" for w in packet["warnings"]))
        self.assertEqual(
            packet["recommended_action"],
            "add_or_update_originality_and_dupe_distinction_before_filing",
        )
        duplicate = self._silent(packet, "duplicate")
        self.assertTrue(duplicate["matched"])
        self.assertIn("workspace title/root-cause overlap", duplicate["evidence_phrases"])
        self.assertTrue(duplicate["suggested_strengthening"])

    def test_no_match_returns_advisory_not_approval(self) -> None:
        packet = self._packet(
            """# Vault share accounting invariant break

Severity: Medium

A non-privileged depositor can trigger a persistent share accounting mismatch
with a fork test and a concrete asset delta.
"""
        )
        self.assertEqual(packet["matched_patterns"], [])
        self.assertEqual(packet["warnings"][0]["code"], "triager_precheck_no_match")
        self.assertEqual(packet["disposition_evidence"]["disposition"], "no_local_rejection_pattern")
        self.assertEqual(packet["disposition_evidence"]["confidence"], 0.0)
        self.assertEqual(
            packet["recommended_action"],
            "proceed_with_normal_pre_submit_checks",
        )
        self.assertEqual(packet["silent_kill_summary"]["predicted_classes"], [])
        self.assertFalse(self._silent(packet, "duplicate")["matched"])


# r36-rebuttal: lane-TRIAGER-MINDSET-WIRE registered via tools/agent-pathspec-register.py
class TriagerPrecheckRule62NewPatternsTest(unittest.TestCase):
    """Tests for the 6 new patterns R18-R23 added 2026-05-26 by lane
    TRIAGER-MINDSET-WIRE (Rule 62 codification).

    Each pattern's empirical anchor:
      R18 -> DRILL-6 (Hyperbridge pallet-relayer u256 truncation)
      R19 -> Spark v10 cooperative-exit (multi-actor defender narrative)
      R20 -> dYdX cantina-213 (in-process microbench)
      R21 -> dYdX cantina-201/202 (fault shim)
      R22 -> Polymarket cantina-84 (POLY_1271 restricted population)
      R23 -> Hyperbridge OP L2Oracle (designed-as-intended Informative)
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ws = self.root / "workspace"
        self.ws.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _draft(self, body: str, name: str = "draft.md") -> Path:
        path = self.ws / name
        path.write_text(body, encoding="utf-8")
        return path

    def _packet(self, body: str, name: str = "draft.md") -> dict:
        return _sim.build_precheck(self._draft(body, name=name), self.ws)

    def _ids(self, packet: dict) -> set[str]:
        return {str(row.get("id")) for row in packet["matched_patterns"]}

    # ------------------------------------------------------------------
    # R18 - Token-economics structural bound (DRILL-6 anchor)
    # ------------------------------------------------------------------
    def test_r18_token_economics_structural_bound_matches(self) -> None:
        packet = self._packet(
            """# Pallet-relayer u256 to u128 truncation

Severity: Medium

The pallet-relayer truncates u256 to u128 in the burn accounting. The
finding is structurally unreachable in production because the bridge
supply is far below u128::MAX.
"""
        )
        self.assertIn("R18", self._ids(packet))

    def test_r18_class_vote_lands_in_reachability(self) -> None:
        packet = self._packet(
            """# Bridge supply structural bound

Severity: High

The exploit requires bridge supply far below u128::MAX, structurally
unreachable under current token economics.
"""
        )
        self.assertGreater(packet["class_votes"]["F_prime_reachability_realism"], 0)

    # ------------------------------------------------------------------
    # R19 - Multi-actor defender narrative (Spark v10 anchor)
    # ------------------------------------------------------------------
    def test_r19_multi_actor_defender_narrative_matches(self) -> None:
        packet = self._packet(
            """# Spark cooperative-exit chain-watcher gap

Severity: Critical

The honest SSP broadcasts tx-real to spend the multisig leaf.  The
sender produces the signed FROST share that is required for the load-
bearing artifact.
"""
        )
        self.assertIn("R19", self._ids(packet))

    def test_r19_class_vote_lands_in_actor_model(self) -> None:
        packet = self._packet(
            """# Defender narrative gap

Severity: High

We argue that the watchtower will catch this and the sequencer
broadcasts the rescue tx, but the attacker is in the signer set.
"""
        )
        # R19 maps to F_no_fund_impact_or_actor_model (actor-model axis).
        self.assertGreater(packet["class_votes"]["F_no_fund_impact_or_actor_model"], 0)

    # ------------------------------------------------------------------
    # R20 - In-process microbench (cantina-213 anchor)
    # ------------------------------------------------------------------
    def test_r20_in_process_microbench_matches(self) -> None:
        packet = self._packet(
            """# Codec sub-call cap CheckTx microbench

Severity: High

The PoC shows in-process contention with a function-local microbenchmark.
No external mempool ingress; this is a single-process artifact and does
not produce node-level reproduction.
"""
        )
        self.assertIn("R20", self._ids(packet))

    def test_r20_class_vote_lands_in_production_grade(self) -> None:
        packet = self._packet(
            """# Production-runtime impact via in-process timing

Severity: High

The PoC is a function-local microbenchmark; we measure timing in-process.
No node-level reproduction is provided yet.
"""
        )
        self.assertGreater(
            packet["class_votes"]["E_production_grade_evidence_gap"], 0
        )

    # ------------------------------------------------------------------
    # R21 - Fault-shim manufactured impact (cantina-201/202 anchor)
    # ------------------------------------------------------------------
    def test_r21_fault_shim_matches(self) -> None:
        packet = self._packet(
            """# AB-BA deadlock proof

Severity: Critical

The PoC uses slowBatchDB and memdb only with a custom latency shim
around batch writes.  Does not reproduce on real backend.
"""
        )
        self.assertIn("R21", self._ids(packet))

    def test_r21_class_vote_lands_in_production_grade(self) -> None:
        packet = self._packet(
            """# Storage race needing real backend

Severity: High

Uses slowBatchDB with timing wrapper and monkey-patched scheduler. Walks
back on production profile when real DB is used.
"""
        )
        self.assertGreater(
            packet["class_votes"]["E_production_grade_evidence_gap"], 0
        )

    # ------------------------------------------------------------------
    # R22 - OOS trusted-infra / restricted population (Polymarket anchor)
    # ------------------------------------------------------------------
    def test_r22_oos_trusted_infra_or_restricted_population_matches(self) -> None:
        packet = self._packet(
            """# Signature replay against POLY 1271 wallets

Severity: High

POLY_1271 restricted to Deposit Wallets, which are a non-default wallet
type.  Specific wallet population requirement makes this a specific
deployment topology issue.
"""
        )
        self.assertIn("R22", self._ids(packet))

    def test_r22_class_vote_lands_in_oos_infra(self) -> None:
        packet = self._packet(
            """# Proposer infra compromise

Severity: Critical

The exploit requires compromise of off-chain infrastructure is OOS per
the program rules; sidecar compromise OOS.
"""
        )
        self.assertGreater(packet["class_votes"]["D_oos_infra_or_deployment"], 0)

    # ------------------------------------------------------------------
    # R23 - Acknowledged-by-design omission (Hyperbridge OP anchor)
    # ------------------------------------------------------------------
    def test_r23_acknowledged_by_design_matches(self) -> None:
        packet = self._packet(
            """# OP L2 oracle missing finalization check

Severity: High

The L2Oracle path lacks an in-verifier finalization check.  The
behavior is designed-as-intended per the docs; acknowledged risk
documented in SECURITY.md.
"""
        )
        self.assertIn("R23", self._ids(packet))

    def test_r23_class_vote_lands_in_designed_as_intended(self) -> None:
        packet = self._packet(
            """# Missing verification because design choice

Severity: High

The contested behavior is documented design choice; centralization risks
acknowledged by design.
"""
        )
        self.assertGreater(packet["class_votes"]["C_designed_as_intended"], 0)

    # ------------------------------------------------------------------
    # Bulk: ensure all 6 new pattern IDs are loaded from JSON
    # ------------------------------------------------------------------
    def test_all_six_new_patterns_loaded(self) -> None:
        patterns = _sim.load_triager_patterns()
        ids = {p["id"] for p in patterns}
        for new_id in ("R18", "R19", "R20", "R21", "R22", "R23"):
            self.assertIn(new_id, ids, f"{new_id} missing from patterns")

    def test_all_six_new_patterns_have_outcome_class_mapping(self) -> None:
        for new_id in ("R18", "R19", "R20", "R21", "R22", "R23"):
            self.assertIn(new_id, _sim.OUTCOME_CLASS_BY_PATTERN_ID)


class TriagerPrecheckCliTest(unittest.TestCase):
    def test_cli_emits_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            ws.mkdir()
            draft = ws / "draft.md"
            draft.write_text(
                "# Event-only finding\n\nOnly affects event emission; no functional impact.",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "triager-pre-filing-simulator.py"),
                    "--draft",
                    str(draft),
                    "--workspace",
                    str(ws),
                ],
                check=True,
                env={**os.environ, "AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        packet = json.loads(proc.stdout)
        self.assertEqual(packet["schema"], "auditooor.triager_precheck_rules.v1")
        self.assertFalse(packet["local_rules_status"]["provider_backed"])
        self.assertFalse(packet["local_rules_status"]["provider_call_made"])
        self.assertFalse(packet["provider_status"]["provider_backed"])
        self.assertFalse(packet["provider_status"]["provider_call_made"])
        self.assertFalse(packet["capability_boundary"]["provider_backed_simulation"])
        self.assertIsNone(packet["predicted_verdict"])
        self.assertIn("reference/triager_patterns.json", packet["source_refs"])
        self.assertIn("reference/triager_disposition_classifier.json", packet["source_refs"])

    def test_cli_accepts_uppercase_severity_no_argparse_rc2(self) -> None:
        # Regression: pre-submit-check.sh Check #114 passes an all-uppercase
        # SEVERITY (MEDIUM/HIGH/CRITICAL). The old argparse `choices` list only
        # allowed title-case / lower-case, so uppercase exited rc=2 and the
        # shell reported "simulator returned rc=2; skipping (advisory)" on every
        # draft. Any casing must now exit rc=0 and emit valid JSON; only a
        # genuinely-unknown value exits non-zero.
        # r36-rebuttal: lane r62-sim-fix declared in .auditooor/agent_pathspec.json
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            ws.mkdir()
            draft = ws / "draft.md"
            draft.write_text(
                "# Some finding\n\nA permanent freezing of funds occurs.",
                encoding="utf-8",
            )
            tool = str(REPO_ROOT / "tools" / "triager-pre-filing-simulator.py")
            for sev in ("MEDIUM", "HIGH", "CRITICAL", "medium", "Critical"):
                proc = subprocess.run(
                    [sys.executable, tool, "--draft", str(draft),
                     "--workspace", str(ws), "--severity", sev],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                self.assertEqual(proc.returncode, 0, f"severity={sev} rc={proc.returncode} stderr={proc.stderr}")
                packet = json.loads(proc.stdout)
                self.assertEqual(packet["schema"], "auditooor.triager_precheck_rules.v1")
                self.assertEqual(packet["claimed_severity"], sev.capitalize())
            # Unknown severity must still be rejected (clean SystemExit, not silent pass).
            bad = subprocess.run(
                [sys.executable, tool, "--draft", str(draft),
                 "--workspace", str(ws), "--severity", "BOGUS"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertNotEqual(bad.returncode, 0)

    def test_provider_backed_cli_with_mock_dispatcher_emits_advisory_prediction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            draft = ws / "draft.md"
            draft.write_text(
                "# Event-only finding\n\nOnly affects event emission; no functional impact.",
                encoding="utf-8",
            )
            dispatcher = root / "mock_dispatcher.py"
            dispatcher.write_text(
                "import json\n"
                "print(json.dumps({\n"
                "  'predicted_verdict': 'needs_more_proof',\n"
                "  'confidence': 0.72,\n"
                "  'killer_phrase': 'no functional impact',\n"
                "  'suggested_strengthening': 'prove non-self fund impact',\n"
                "  'rationale': 'local rules matched event-only risk'\n"
                "}))\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "triager-pre-filing-simulator.py"),
                    "--draft",
                    str(draft),
                    "--workspace",
                    str(ws),
                    "--provider-backed",
                    "--provider",
                    "kimi",
                    "--dispatcher",
                    str(dispatcher),
                ],
                check=True,
                env={**os.environ, "AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        packet = json.loads(proc.stdout)
        self.assertEqual(packet["mode"], "provider_backed_simulation")
        self.assertFalse(packet["local_rules_status"]["provider_backed"])
        self.assertFalse(packet["disposition_evidence"]["provider_backed"])
        self.assertEqual(packet["disposition_evidence"]["predicted_provider_verdict"], None)
        self.assertTrue(packet["provider_status"]["provider_backed"])
        self.assertTrue(packet["provider_status"]["provider_call_made"])
        self.assertTrue(packet["provider_status"]["predicted_verdict_supported"])
        self.assertTrue(packet["capability_boundary"]["provider_backed_simulation"])
        self.assertEqual(packet["predicted_verdict"]["predicted_verdict"], "needs_more_proof")
        self.assertEqual(packet["predicted_verdict"]["killer_phrase"], "no functional impact")
        self.assertTrue(packet["provider_advisory_only"])

    def test_provider_backed_cli_with_failing_dispatcher_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            draft = ws / "draft.md"
            draft.write_text("# Finding\n\nConcrete proof pending.", encoding="utf-8")
            dispatcher = root / "mock_dispatcher_fail.py"
            dispatcher.write_text(
                "import sys\n"
                "print('{\"reason\":\"cannot-run: no-api-key\"}', file=sys.stderr)\n"
                "raise SystemExit(2)\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "triager-pre-filing-simulator.py"),
                    "--draft",
                    str(draft),
                    "--workspace",
                    str(ws),
                    "--provider-backed",
                    "--dispatcher",
                    str(dispatcher),
                ],
                check=True,
                env={**os.environ, "AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        packet = json.loads(proc.stdout)
        self.assertEqual(packet["mode"], "provider_backed_simulation_blocked")
        self.assertFalse(packet["local_rules_status"]["provider_backed"])
        self.assertEqual(packet["provider_status"]["state"], "blocked")
        self.assertFalse(packet["provider_status"]["provider_backed"])
        self.assertTrue(packet["provider_status"]["provider_call_made"])
        self.assertTrue(packet["provider_status"]["dispatcher_attempted"])
        self.assertFalse(packet["provider_status"]["predicted_verdict_supported"])
        self.assertFalse(packet["capability_boundary"]["provider_dispatch"])
        self.assertFalse(packet["capability_boundary"]["provider_backed_simulation"])
        self.assertFalse(packet["capability_boundary"]["predicted_triager_verdict"])
        self.assertNotIn("predicted_verdict", packet)
        self.assertIn("cannot-run", packet["provider_status"]["error"])

    def test_provider_backed_cli_dispatcher_override_requires_test_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            draft = ws / "draft.md"
            draft.write_text("# Finding\n\nConcrete proof pending.", encoding="utf-8")
            dispatcher = root / "mock_dispatcher.py"
            dispatcher.write_text("print('{}')\n", encoding="utf-8")
            env = dict(os.environ)
            env.pop("AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER", None)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "triager-pre-filing-simulator.py"),
                    "--draft",
                    str(draft),
                    "--workspace",
                    str(ws),
                    "--provider-backed",
                    "--dispatcher",
                    str(dispatcher),
                ],
                check=False,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("test-only", proc.stderr)

    def test_provider_backed_cli_nonzero_dispatcher_stdout_json_still_blocks_prediction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            draft = ws / "draft.md"
            draft.write_text("# Finding\n\nConcrete proof pending.", encoding="utf-8")
            dispatcher = root / "mock_dispatcher_fail_with_stdout.py"
            dispatcher.write_text(
                "import json\n"
                "print(json.dumps({'predicted_verdict':'likely_accept','confidence':0.99}))\n"
                "raise SystemExit(2)\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "triager-pre-filing-simulator.py"),
                    "--draft",
                    str(draft),
                    "--workspace",
                    str(ws),
                    "--provider-backed",
                    "--dispatcher",
                    str(dispatcher),
                ],
                check=True,
                env={**os.environ, "AUDITOOOR_MCP_ALLOW_TEST_DISPATCHER": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        packet = json.loads(proc.stdout)
        self.assertEqual(packet["mode"], "provider_backed_simulation_blocked")
        self.assertFalse(packet["provider_status"]["predicted_verdict_supported"])
        self.assertFalse(packet["capability_boundary"]["predicted_triager_verdict"])
        self.assertNotIn("predicted_verdict", packet)


if __name__ == "__main__":
    unittest.main()
