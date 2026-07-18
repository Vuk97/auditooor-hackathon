#!/usr/bin/env python3
"""Tests for tools/brain-prime.py — Wave-8 brain-prime user-facing payoff.

Covers:
  T1: Layer-1 MCP recall block fires (10 callables attempted; failures
      logged but don't crash) — driven via --skip-mcp path + sentinel
      callable-count assertion when run live (best-effort).
  T2: Function extraction works for a Go fixture.
  T3: Cross-engagement fanout invocation works (load_source_patterns +
      scan_destination wired in).
  T4: Report sections all present + well-formed (Phase A..F headers).
  T5: --max-files truncates correctly.
  T6: --top-functions-per-file truncates correctly.
  T7: heuristic_scope_resolution picks Go protocol/x style when present.
  T8: phase F lane proposal handles empty inputs without crashing.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "brain-prime.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("brain_prime_for_test",
                                                  MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["brain_prime_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


BP = _load()


GO_SAMPLE = textwrap.dedent("""\
    package keeper

    import (
        sdk "github.com/cosmos/cosmos-sdk/types"
    )

    type msgServer struct {
        Keeper
    }

    func (k msgServer) RegisterAffiliate(
        ctx context.Context,
        msg *types.MsgRegisterAffiliate,
    ) (*types.MsgRegisterAffiliateResponse, error) {
        if msg.Affiliate == k.GetAuthority() {
            return nil, fmt.Errorf("authority cannot self-register")
        }
        k.SetAffiliate(ctx, msg.Affiliate)
        return &types.MsgRegisterAffiliateResponse{}, nil
    }

    func (k msgServer) UpdateAffiliateTiers(
        ctx context.Context,
        msg *types.MsgUpdateAffiliateTiers,
    ) (*types.MsgUpdateAffiliateTiersResponse, error) {
        return &types.MsgUpdateAffiliateTiersResponse{}, nil
    }

    func helper() bool {
        return true
    }
""")


def _make_workspace(tmpdir: Path) -> Path:
    ws = tmpdir / "test-engagement"
    (ws / "external" / "v4-chain" / "protocol" / "x" / "affiliates" / "keeper").mkdir(parents=True)
    (ws / "external" / "v4-chain" / "protocol" / "x" / "affiliates" / "keeper" / "msg_server.go").write_text(GO_SAMPLE)
    (ws / "INTAKE_BASELINE.md").write_text(
        "# Intake Baseline\n\nAudit-pin: 5ee9766351ef864856a309a971b13fdd98cae2c5\n"
    )
    return ws


def _args_with(**kw) -> argparse.Namespace:
    defaults = {
        "workspace": "",
        "target_repo": None,
        "language": None,
        "scope_globs": None,
        "top_functions_per_file": 5,
        "min_confidence": 0.0,
        "max_files": 50,
        "out": None,
        "receipt_out": None,
        "no_receipt": False,
        "strict": False,
        "skip_mcp": True,
        "mcp_timeout": 5.0,
        "json": False,
    }
    defaults.update(kw)
    return argparse.Namespace(**defaults)


class TestBrainPrime(unittest.TestCase):

    # ------------------------------------------------------------------ #
    # T1: MCP recall block (skip-mcp short-circuit; structure preserved) #
    # ------------------------------------------------------------------ #
    def test_t1_mcp_skip_records_structure(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            args = _args_with(workspace=str(ws), skip_mcp=True)
            summary = BP.run_brain_prime(args)
            self.assertIn("phase_a", summary)
            self.assertTrue(summary["phase_a"].get("skipped"))
            self.assertEqual(summary["phase_a"]["callables_attempted"], 0)
        # Bonus: verify the canonical 10-callable list is registered.
        self.assertEqual(len(BP.LAYER1_CALLABLES), 10)
        names = [n for n, _ in BP.LAYER1_CALLABLES]
        for required in (
            "vault_resume_context", "vault_exploit_context",
            "vault_knowledge_gap_context", "vault_engagement_status",
            "vault_harness_context", "vault_outcome_context",
            "vault_dispatch_context", "vault_goal_state",
            "vault_next_loop", "vault_llm_calibration",
        ):
            self.assertIn(required, names)

    def test_t1b_receipt_writer_emits_integrity_fields(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            report_path = ws / "BRAIN_PRIMING_REPORT.md"
            report_text = "# Brain Priming Report\n\nfixture\n"
            report_path.write_text(report_text, encoding="utf-8")
            args = _args_with(
                workspace=str(ws),
                top_functions_per_file=2,
                min_confidence=0.25,
                max_files=3,
            )
            receipt = BP.build_brain_prime_receipt(
                workspace=ws,
                engagement="test-engagement",
                report_path=report_path,
                report_text=report_text,
                audit_pin="5ee9766351ef864856a309a971b13fdd98cae2c5",
                target_repo="dydxprotocol/v4-chain",
                phase_a={
                    "context_pack_id": "ctx",
                    "context_pack_hash": "hash",
                    "callables_attempted": 10,
                    "callables_succeeded": 10,
                    "callables_failed": [],
                    "duration_seconds": 1.5,
                    "skipped": False,
                },
                scope={
                    "scope_globs": "external/*/protocol/x/**/*.go",
                    "language": "go",
                    "auto_detected": True,
                    "candidate_dirs": [str(ws / "external" / "v4-chain" / "protocol" / "x")],
                },
                functions_extracted=7,
                phase_d_files=2,
                phase_e_sources=1,
                phase_f=[{
                    "lane_id": "LANE-H1",
                    "attack_class": "admin-bypass",
                    "max_confidence": 0.9,
                    "severity_guess": "CRITICAL/HIGH",
                    "provenance": "fixture",
                }],
                args=args,
            )
            path = BP.write_brain_prime_receipt(ws, receipt)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.brain_prime_receipt.v1")
            self.assertEqual(Path(payload["workspace_path"]).resolve(), ws.resolve())
            self.assertEqual(payload["report_sha256"], BP._sha256_text(report_text))
            self.assertIn("receipt_hash", payload)
            self.assertTrue(payload["summary"]["strict_ready"])
            ok, reason = BP.validate_receipt_strict_ready(path)
            self.assertTrue(ok, reason)

    def test_t1c_strict_receipt_validator_rejects_not_ready(self):
        with tempfile.TemporaryDirectory() as td:
            receipt_path = Path(td) / "receipt.json"
            receipt_path.write_text(
                json.dumps({
                    "schema": "auditooor.brain_prime_receipt.v1",
                    "summary": {"strict_ready": False},
                }),
                encoding="utf-8",
            )
            ok, reason = BP.validate_receipt_strict_ready(receipt_path)
            self.assertFalse(ok)
            self.assertIn("strict_ready", reason)

    def test_t1d_strict_receipt_validator_rejects_missing_receipt(self):
        ok, reason = BP.validate_receipt_strict_ready(None)
        self.assertFalse(ok)
        self.assertIn("missing receipt_path", reason)

    # ------------------------------------------------------------------ #
    # T2: Function extraction works on Go fixture                        #
    # ------------------------------------------------------------------ #
    def test_t2_go_function_extraction(self):
        sig_mod = BP.load_sig_extractor()
        recs = sig_mod.extract_go_functions(GO_SAMPLE, "msg_server.go")
        names = [r["function_name"] for r in recs]
        self.assertIn("RegisterAffiliate", names)
        self.assertIn("UpdateAffiliateTiers", names)
        self.assertIn("helper", names)
        # The Register function should have authority-check guard detected
        reg = next(r for r in recs if r["function_name"] == "RegisterAffiliate")
        self.assertTrue(any("authority" in g for g in reg["guards_detected"]))

    # ------------------------------------------------------------------ #
    # T3: Cross-engagement fanout invocation works                       #
    # ------------------------------------------------------------------ #
    def test_t3_fanout_invocation(self):
        fanout_mod = BP.load_fanout()
        # Confirm canonical entrypoints are present
        self.assertTrue(hasattr(fanout_mod, "load_source_patterns"))
        self.assertTrue(hasattr(fanout_mod, "scan_destination"))
        # Phase-E end-to-end: should not crash with synthetic ws
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            result = BP.phase_e_fanout("test-engagement", ws,
                                       fanout_mod, top_n=5)
            self.assertIsInstance(result, dict)

    # ------------------------------------------------------------------ #
    # T3b: fanout NEVER hangs - an overall wall-clock budget bounds the    #
    # whole phase so a slow/unbounded per-root scan (e.g. a vendored       #
    # dependencies/ tree, which timed brain-prime out on hyperlane,        #
    # EXIT=124, no receipt) is cut off and the receipt write continues.    #
    # ------------------------------------------------------------------ #
    def test_t3b_fanout_overall_budget_bounds_scan(self):
        import time as _time

        captured_budgets: List[Any] = []

        class _SlowFanout:
            """Stub: one prior engagement, a scan that respects the budget it
            is handed (records it, and 'spends' a chunk of wall-clock)."""

            def list_prior_engagements_unused(self):  # pragma: no cover
                return ["e1", "e2", "e3"]

            def load_source_patterns(self, src):
                return ["pat"]

            def scan_destination(self, patterns, dest_root, top_n=10,
                                 max_dest_files=None, budget_seconds=None):
                captured_budgets.append(budget_seconds)
                # emulate a scan that would run long if unbounded
                _time.sleep(0.05)
                return []

        # Force a multi-prior, multi-root walk by monkeypatching the prior list
        # + dest-root resolver to non-empty fixtures.
        orig_priors = BP.list_prior_engagements
        orig_roots = BP._resolve_fanout_dest_roots
        BP.list_prior_engagements = lambda _self_eng: ["e1", "e2", "e3", "e4"]
        BP._resolve_fanout_dest_roots = lambda ws, globs: [ws]
        try:
            with tempfile.TemporaryDirectory() as td:
                ws = Path(td)
                start = _time.monotonic()
                result = BP.phase_e_fanout(
                    "this-eng", ws, _SlowFanout(), top_n=5,
                    budget_seconds=0.2,
                )
                elapsed = _time.monotonic() - start
            self.assertIsInstance(result, dict)
            # The whole phase respected the 0.2s overall budget (with slack).
            self.assertLess(elapsed, 2.0)
            # Every per-root scan was handed a POSITIVE bounded budget, never
            # the unbounded None that caused the hang.
            self.assertTrue(captured_budgets, "scan_destination never called")
            for b in captured_budgets:
                self.assertIsNotNone(b)
                self.assertGreater(b, 0)
        finally:
            BP.list_prior_engagements = orig_priors
            BP._resolve_fanout_dest_roots = orig_roots

    def test_t3c_fanout_default_budget_applied_when_none(self):
        # When budget_seconds is None (the Makefile default), the phase still
        # hands a bounded positive budget to each scan (the default), so it can
        # never spin unbounded.
        captured: List[Any] = []

        class _Stub:
            def load_source_patterns(self, src):
                return ["p"]

            def scan_destination(self, patterns, dest_root, top_n=10,
                                 max_dest_files=None, budget_seconds=None):
                captured.append(budget_seconds)
                return []

        orig_priors = BP.list_prior_engagements
        orig_roots = BP._resolve_fanout_dest_roots
        BP.list_prior_engagements = lambda _e: ["e1"]
        BP._resolve_fanout_dest_roots = lambda ws, globs: [ws]
        try:
            with tempfile.TemporaryDirectory() as td:
                BP.phase_e_fanout("e", Path(td), _Stub(), budget_seconds=None)
            self.assertTrue(captured)
            self.assertIsNotNone(captured[0])
            self.assertGreater(captured[0], 0)
        finally:
            BP.list_prior_engagements = orig_priors
            BP._resolve_fanout_dest_roots = orig_roots

    # ------------------------------------------------------------------ #
    # T4: Report sections present + well-formed                          #
    # ------------------------------------------------------------------ #
    def test_t4_report_sections_present(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            args = _args_with(workspace=str(ws), skip_mcp=True)
            summary = BP.run_brain_prime(args)
            report = Path(summary["report_path"]).read_text(encoding="utf-8")
            for header in (
                "# Brain Priming Report",
                "## Phase A — Layer-1 MCP recall summary",
                "## Phase B — Scope resolution",
                "## Phase C — Function signature extraction",
                "## Phase D — Top-ranked attack hypotheses per function",
                "## Phase E — Cross-engagement fanout candidates",
                "## Phase F — Recommended hunt lanes (consolidated)",
                "## Caveats — what the brain doesn't know",
            ):
                self.assertIn(header, report,
                              f"missing header: {header}")
            # Audit-pin should be picked up from INTAKE_BASELINE.md
            self.assertIn("5ee9766351ef864856a309a971b13fdd98cae2c5", report)

    # ------------------------------------------------------------------ #
    # T5: --max-files truncates                                          #
    # ------------------------------------------------------------------ #
    def test_t5_max_files_truncates(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            # Add multiple Go files
            base = ws / "external" / "v4-chain" / "protocol" / "x" / "affiliates" / "keeper"
            for i in range(8):
                (base / f"extra_{i}.go").write_text(GO_SAMPLE)
            args = _args_with(workspace=str(ws), skip_mcp=True, max_files=2)
            summary = BP.run_brain_prime(args)
            # Phase D should have at most 2 files
            self.assertLessEqual(summary["phase_d_files"], 2)

    # ------------------------------------------------------------------ #
    # T6: --top-functions-per-file truncates                             #
    # ------------------------------------------------------------------ #
    def test_t6_top_functions_per_file_truncates(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            args = _args_with(workspace=str(ws), skip_mcp=True,
                              top_functions_per_file=1)
            summary = BP.run_brain_prime(args)
            # Open report and confirm only ONE function block per file
            report = Path(summary["report_path"]).read_text(encoding="utf-8")
            # Each Phase-D file section has "### `<path>`" followed by one
            # "#### `<fn>`" — count #### occurrences and compare.
            triple_count = report.count("\n#### `")
            self.assertLessEqual(triple_count, summary["phase_d_files"])

    # ------------------------------------------------------------------ #
    # T7: heuristic scope picks Go cosmos style                          #
    # ------------------------------------------------------------------ #
    def test_t7_heuristic_scope_go(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            lang, glob, dirs = BP.heuristic_scope_resolution(ws, "")
            self.assertEqual(lang, "go")
            self.assertIn("protocol/x", glob)
            self.assertTrue(dirs)

    def test_t7b_heuristic_scope_src_mixed_rust_solidity(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "mixed-engagement"
            (ws / "src" / "hyperbridge" / "crates" / "ismp" / "src").mkdir(parents=True)
            (ws / "src" / "hyperbridge" / "crates" / "ismp" / "src" / "lib.rs").write_text(
                "pub fn verify_proof() -> bool { true }\n",
                encoding="utf-8",
            )
            (ws / "src" / "solidity-merkle-trees" / "src").mkdir(parents=True)
            (ws / "src" / "solidity-merkle-trees" / "src" / "Merkle.sol").write_text(
                "contract Merkle { function verify(bytes32 root) external {} }\n",
                encoding="utf-8",
            )

            lang, glob, dirs = BP.heuristic_scope_resolution(ws, "")
            self.assertEqual(lang, "mixed")
            self.assertIn("src/*/**/*.rs", glob)
            self.assertIn("src/*/**/*.sol", glob)
            self.assertTrue(dirs)

    # ------------------------------------------------------------------ #
    # T8: Phase F lane proposal handles empty inputs                     #
    # ------------------------------------------------------------------ #
    def test_t8_phase_f_empty_inputs(self):
        # Should return empty list, not crash
        lanes = BP._propose_hunt_lanes({}, {}, max_lanes=5)
        self.assertEqual(lanes, [])
        # Phase-D only, no Phase-E
        d = {
            "x/affiliates/keeper/msg_server.go": [{
                "function_name": "RegisterAffiliate",
                "line_start": 12,
                "shape_hash": "abcd1234",
                "ranked_attack_classes": [
                    {"attack_class": "admin-bypass", "confidence": 0.78},
                    {"attack_class": "blocked-addr-bypass", "confidence": 0.61},
                ],
            }],
        }
        lanes = BP._propose_hunt_lanes(d, {}, max_lanes=3)
        self.assertTrue(lanes)
        self.assertEqual(lanes[0]["attack_class"], "admin-bypass")
        # Detector-shape lanes are tagged.
        for lane in lanes:
            self.assertEqual(lane["lane_kind"], "detector_shape")


# --------------------------------------------------------------------------- #
# V3 gap #4 / Lane-L: component-aware (architectural) hunt lanes               #
# --------------------------------------------------------------------------- #


def _synthetic_system_model() -> Dict[str, Any]:
    """A system_model.json shaped like tools/system-model.py emits, with
    Sei-style high-value architectural surfaces."""
    return {
        "schema": "auditooor.system_model.v1",
        "generated_at": "2026-05-22T00:00:00Z",
        "workspace_path": "/tmp/sei",
        "extraction": {"source_files_indexed": 42,
                       "languages": {"go": 30, "solidity": 12}},
        "components": [
            {"name": "bank_precompile", "path": "precompiles/bank/bank.go",
             "language": "go", "loc": 320,
             "responsibility": "custom EVM precompile bridging to x/bank"},
            {"name": "occ_scheduler", "path": "occ/scheduler.go",
             "language": "go", "loc": 510,
             "responsibility": "optimistic parallel execution scheduler"},
            {"name": "pointer", "path": "evm/pointer/pointer.go",
             "language": "go", "loc": 210,
             "responsibility": "pointer contract registry"},
            {"name": "logger", "path": "util/logger.go", "language": "go",
             "loc": 40, "responsibility": "logging helper"},
        ],
        "asset_value_flows": {
            "ingress_signal_paths": ["precompiles/bank/bank.go"],
            "egress_signal_paths": ["evm/pointer/pointer.go"],
            "custody_and_flow_map": {
                "status": "needs_operator_or_agent_review", "detail": "..."},
        },
        "trust_boundaries": {
            "status": "needs_operator_or_agent_review",
            "detail": "enumerate cross-component validation assumptions"},
        "privileged_roles": [
            {"role": "onlyGovernance", "declared_in": ["gov/keeper.go"],
             "capabilities": {"status": "needs_operator_or_agent_review",
                              "detail": "..."}},
        ],
        "protocol_owned_defenses": [
            {"family": "pause", "extraction": "mechanical_keyword",
             "source_signal_paths": ["gov/keeper.go"]},
        ],
        "state_machines": [],
        "claimed_invariants": {"status": "needs_operator_or_agent_review",
                               "detail": "..."},
    }


class TestBrainPrimeComponentAwareLanes(unittest.TestCase):

    # T9: with a system model, Phase F emits architectural lanes citing
    # the high-value components.
    def test_t9_architectural_lanes_emitted_from_system_model(self):
        sm = _synthetic_system_model()
        lanes = BP._propose_hunt_lanes({}, {}, max_lanes=8, system_model=sm)
        self.assertTrue(lanes)
        arch = [l for l in lanes if l["lane_kind"] == "architectural"]
        self.assertTrue(arch, "expected at least one architectural lane")
        # The bank precompile and OCC scheduler should both surface.
        joined = " ".join(l["attack_class"] for l in arch)
        self.assertIn("precompiles/bank/bank.go", joined)
        self.assertIn("occ/scheduler.go", joined)
        # The plain logger helper must NOT become a lane (not high-value).
        self.assertNotIn("util/logger.go", joined)
        # Every architectural lane cites a system-model section.
        for l in arch:
            self.assertIn(l["model_section"],
                          ("components", "value-flow", "asset_value_flows",
                           "trust_boundaries", "privileged_roles",
                           "protocol_owned_defenses"))
            self.assertTrue(l["component"])

    # T10: architectural lanes rank ABOVE detector-shape lanes.
    def test_t10_architectural_lanes_rank_above_detector_lanes(self):
        sm = _synthetic_system_model()
        d = {
            "x/foo/keeper.go": [{
                "function_name": "Handle",
                "line_start": 10,
                "shape_hash": "h",
                "ranked_attack_classes": [
                    {"attack_class": "timestamp-manipulation",
                     "confidence": 0.9},
                ],
            }],
        }
        lanes = BP._propose_hunt_lanes(d, {}, max_lanes=8, system_model=sm)
        kinds = [l["lane_kind"] for l in lanes]
        # First lane is architectural; detector lanes come after.
        self.assertEqual(kinds[0], "architectural")
        first_detector = next((i for i, k in enumerate(kinds)
                                if k == "detector_shape"), None)
        last_arch = max((i for i, k in enumerate(kinds)
                         if k == "architectural"), default=-1)
        if first_detector is not None:
            self.assertGreater(first_detector, last_arch)
        # lane_id sequence is contiguous.
        self.assertEqual([l["lane_id"] for l in lanes],
                         [f"LANE-H{i}" for i in range(1, len(lanes) + 1)])

    # T11: no system model -> no architectural lanes, detector lanes still
    # work, no crash, no regression.
    def test_t11_no_system_model_keeps_detector_lanes(self):
        d = {
            "x/foo/keeper.go": [{
                "function_name": "Handle",
                "line_start": 10,
                "shape_hash": "h",
                "ranked_attack_classes": [
                    {"attack_class": "deadline-bypass", "confidence": 0.7},
                ],
            }],
        }
        lanes = BP._propose_hunt_lanes(d, {}, max_lanes=8, system_model=None)
        self.assertTrue(lanes)
        self.assertTrue(all(l["lane_kind"] == "detector_shape"
                            for l in lanes))
        # Empty inputs + no model still returns [], no crash.
        self.assertEqual(
            BP._propose_hunt_lanes({}, {}, max_lanes=5, system_model=None), [])

    # T12: trust-boundary / value-flow / privileged-role / protocol-defense
    # lanes are all derived from their respective sections.
    def test_t12_all_model_sections_produce_lanes(self):
        sm = _synthetic_system_model()
        lanes = BP._propose_architectural_lanes(sm, max_lanes=20)
        sections = {l["model_section"] for l in lanes}
        self.assertIn("components", sections)
        self.assertIn("value-flow", sections)
        self.assertIn("trust_boundaries", sections)
        self.assertIn("privileged_roles", sections)
        self.assertIn("protocol_owned_defenses", sections)

    # T12b: test-file / script components must NOT produce a component lane,
    # even when their path matches a high-value hint. The production sibling
    # in the same directory still produces its lane. Guards S14-brainprime-
    # srcfilter (consumer-side production-source filter on the component walk).
    def test_t12b_test_file_components_dropped(self):
        sm = {
            "schema": "auditooor.system_model.v1",
            "components": [
                # Both match the "bridge" hint via their path.
                {"path": "x/bridge/client_test.go", "name": "client_test",
                 "language": "go", "loc": 80},
                {"path": "x/bridge/client.go", "name": "client",
                 "language": "go", "loc": 320},
                # Solidity test/script suffixes must also be dropped.
                {"path": "src/vault/Vault.t.sol", "name": "Vault.t",
                 "language": "solidity", "loc": 60},
                {"path": "src/vault/Vault.s.sol", "name": "Vault.s",
                 "language": "solidity", "loc": 50},
                {"path": "src/vault/Vault.sol", "name": "Vault",
                 "language": "solidity", "loc": 400},
            ],
        }
        lanes = BP._propose_architectural_lanes(sm, max_lanes=8)
        comps = [str(l["component"]) for l in lanes]
        # No test/script component leaks through.
        self.assertFalse(
            any(c.endswith("_test.go") for c in comps),
            f"_test.go component leaked into lanes: {comps}")
        self.assertFalse(
            any(c.endswith(".t.sol") for c in comps),
            f".t.sol component leaked into lanes: {comps}")
        self.assertFalse(
            any(c.endswith(".s.sol") for c in comps),
            f".s.sol component leaked into lanes: {comps}")
        # The production siblings ARE present.
        self.assertIn("x/bridge/client.go", comps)
        self.assertIn("src/vault/Vault.sol", comps)

    # T13: load_system_model_for_workspace round-trips a written file and
    # rejects absent / bad-schema files.
    def test_t13_load_system_model_for_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "sei"
            (ws / ".auditooor").mkdir(parents=True)
            # Absent -> None.
            self.assertIsNone(BP.load_system_model_for_workspace(ws))
            # Bad schema -> None.
            (ws / ".auditooor" / "system_model.json").write_text(
                json.dumps({"schema": "wrong"}), encoding="utf-8")
            self.assertIsNone(BP.load_system_model_for_workspace(ws))
            # Correct -> dict.
            (ws / ".auditooor" / "system_model.json").write_text(
                json.dumps(_synthetic_system_model()), encoding="utf-8")
            loaded = BP.load_system_model_for_workspace(ws)
            self.assertIsInstance(loaded, dict)
            self.assertEqual(loaded["schema"], "auditooor.system_model.v1")

    # T14: render_report reflects system-model presence — ENABLED note +
    # architectural lane block when present, UNAVAILABLE note when absent.
    # Tested via render_report directly (run_brain_prime invokes the heavy
    # ranker which is slow and orthogonal to this Phase-F wiring).
    def test_t14_report_reflects_system_model_presence(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "sei"
            ws.mkdir(parents=True)
            args = _args_with(workspace=str(ws), skip_mcp=True)
            phase_a = {"context_pack_id": "", "context_pack_hash": "",
                       "callables_attempted": 0, "callables_succeeded": 0,
                       "callables_failed": [], "duration_seconds": 0.0,
                       "skipped": True}
            scope = {"language": "go", "scope_globs": "", "auto_detected": True,
                     "candidate_dirs": []}
            sm = _synthetic_system_model()
            # (a) with system model -> ENABLED note + architectural lanes.
            phase_f = BP._propose_hunt_lanes({}, {}, max_lanes=8, system_model=sm)
            report = BP.render_report(
                workspace=ws, engagement="sei", target_repo="sei/sei-chain",
                audit_pin="", scope=scope, phase_a=phase_a, phase_c_count=0,
                phase_d={}, phase_e={}, phase_f=phase_f, args=args,
                system_model=sm,
            )
            self.assertIn("Component-aware lanes ENABLED", report)
            self.assertIn("[architectural]", report)
            self.assertIn("precompiles/bank/bank.go", report)
            # (b) without system model -> UNAVAILABLE note, detector lanes only.
            phase_f_none = BP._propose_hunt_lanes({}, {}, max_lanes=8,
                                                  system_model=None)
            report_none = BP.render_report(
                workspace=ws, engagement="sei", target_repo="sei/sei-chain",
                audit_pin="", scope=scope, phase_a=phase_a, phase_c_count=0,
                phase_d={}, phase_e={}, phase_f=phase_f_none, args=args,
                system_model=None,
            )
            self.assertIn("Component-aware lanes UNAVAILABLE", report_none)
            self.assertIn("make system-model", report_none)
            self.assertNotIn("[architectural]", report_none)

    # T15: render_report no-system-model path is a no-regression against the
    # default render_report signature (system_model defaults to None).
    def test_t15_render_report_default_signature_no_regression(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "sei"
            ws.mkdir(parents=True)
            args = _args_with(workspace=str(ws), skip_mcp=True)
            phase_a = {"context_pack_id": "", "context_pack_hash": "",
                       "callables_attempted": 0, "callables_succeeded": 0,
                       "callables_failed": [], "duration_seconds": 0.0,
                       "skipped": True}
            scope = {"language": "go", "scope_globs": "", "auto_detected": True,
                     "candidate_dirs": []}
            # Call render_report WITHOUT the system_model kwarg at all.
            report = BP.render_report(
                workspace=ws, engagement="sei", target_repo="",
                audit_pin="", scope=scope, phase_a=phase_a, phase_c_count=0,
                phase_d={}, phase_e={}, phase_f=[], args=args,
            )
            for header in (
                "## Phase F — Recommended hunt lanes (consolidated)",
                "Component-aware lanes UNAVAILABLE",
            ):
                self.assertIn(header, report)


if __name__ == "__main__":
    unittest.main()
