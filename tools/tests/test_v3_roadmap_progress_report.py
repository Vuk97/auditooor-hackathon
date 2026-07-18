#!/usr/bin/env python3
"""Tests for tools/v3-roadmap-progress-report.py."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "v3-roadmap-progress-report.py"


def load_module() -> Any:
    spec = importlib.util.spec_from_file_location("v3_roadmap_progress_report", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload: Any) -> None:
    write(path, json.dumps(payload, indent=2))


class V3RoadmapProgressReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="v3_roadmap_progress_")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def seed_common_tools_and_targets(self) -> None:
        for rels in load_module().NAMED_TOOLS.values():
            for rel in rels:
                write(self.root / rel, "# fixture\n")
        write(
            self.root / "Makefile",
            textwrap.dedent(
                """
                audit-workflow-coverage-map:
                \tpython3 tools/audit-workflow-coverage-map.py --json

                mining-coverage-dashboard:
                \tpython3 tools/mining-coverage-dashboard.py --json

                field-validation-report:
                \tpython3 tools/field-validation-report.py --workspace "$(WS)"

                provider-fanout-discipline-check:
                \tpython3 tools/provider-fanout-discipline-check.py

                v3-provider-campaign-completeness-gate:
                \tpython3 tools/v3-provider-campaign-completeness-gate.py

                lesson-source-inventory:
                \tpython3 tools/lesson-source-inventory.py

                lesson-enforcement-inventory:
                \tpython3 tools/lesson-enforcement-inventory.py

                agent-artifact-lesson-candidates:
                \tpython3 tools/agent-artifact-miner.py

                hackerman-sidecar-coverage-report:
                \tpython3 tools/hackerman-sidecar-coverage-report.py
                """
            ).lstrip(),
        )

    def test_sparse_fixture_reports_ranges_and_all_blocking_categories(self) -> None:
        mod = load_module()
        write(self.root / "Makefile", "audit:\n\tpython3 tools/audit-progress.py\n")

        report = mod.build_report(self.root)

        self.assertEqual(report["schema"], mod.SCHEMA)
        self.assertRegex(report["percent_complete_range"], r"^\d+-\d+%$")
        self.assertRegex(report["percent_left_range"], r"^\d+-\d+%$")
        self.assertNotIn("percent_complete_exact", report)
        self.assertEqual(report["current_blocker_ledger_summary"]["status"], "missing")
        self.assertTrue(report["offline_only"])
        blocking_ids = {row["category_id"] for row in report["blocking_unmet_categories"]}
        self.assertEqual(blocking_ids, set(mod.BLOCKING_CATEGORY_IDS))
        self.assertIn("pillar_p2_causal_chains", blocking_ids)
        self.assertIn("pillar_p3_antipattern_catalog", blocking_ids)
        self.assertIn("pillar_p4_triager_model", blocking_ids)
        self.assertEqual(report["categories"]["field_validation"]["status"], "unmet")
        self.assertEqual(report["categories"]["provider_keep_verification"]["status"], "unknown")

    def test_pillar_statuses_prevent_false_completion(self) -> None:
        mod = load_module()
        self.seed_common_tools_and_targets()
        write_json(
            self.root / "audit" / "corpus_tags" / "derived" / "invariant_library_index.json",
            {
                "schema_version": "auditooor.invariant_library_index.v1",
                "total_invariants": 500,
            },
        )
        write_json(
            self.root / "reports" / "p1" / "library_quality_audit.json",
            {
                "schema_version": "auditooor.p1_library_quality_audit.v1",
                "overall_tp_rate_pct": 50.0,
                "tp_rate_threshold_pct": 60.0,
                "library_verdict": "P1-LIBRARY-TEMPLATE-HEAVY",
            },
        )
        write(
            self.root / "obsidian-vault" / "anti-patterns" / "v2" / "solidity" / "one.yaml",
            "schema_version: auditooor.antipattern_catalog.v1\npattern_id: solidity.one\nquery_type: slither-detector\n",
        )
        write(self.root / "tools" / "antipattern-catalog-build.py", "# fixture\n")
        write(self.root / "reference" / "triager_patterns.json", "[]\n")
        write(self.root / "tools" / "lib" / "triager_precheck_schema.py", "# fixture\n")
        write(self.root / "tools" / "triager-pre-filing-simulator.py", "# fixture\n")
        write(
            self.root / "tools" / "live-target-intelligence-report.py",
            'SCHEMA = "auditooor.live_target_intelligence.v2"\n',
        )
        write(self.root / "tools" / "tests" / "test_live_target_intelligence_report.py", "# fixture\n")
        write(self.root / "tools" / "vault-mcp-server.py", "vault_live_target_report\n")

        report = mod.build_report(self.root)

        self.assertFalse(report["roadmap_complete"])
        self.assertEqual(report["categories"]["pillar_p1_invariants"]["status"], "partial")
        self.assertEqual(report["categories"]["pillar_p2_causal_chains"]["status"], "unmet")
        self.assertEqual(report["categories"]["pillar_p3_antipattern_catalog"]["status"], "partial")
        self.assertEqual(report["categories"]["pillar_p4_triager_model"]["status"], "partial")
        self.assertEqual(report["categories"]["pillar_p5_live_target_intel"]["status"], "partial")
        self.assertIn(
            "MVP2 evidence is present",
            report["categories"]["pillar_p5_live_target_intel"]["reason"],
        )
        blocking_ids = {row["category_id"] for row in report["blocking_unmet_categories"]}
        self.assertIn("pillar_p1_invariants", blocking_ids)
        self.assertIn("pillar_p2_causal_chains", blocking_ids)
        self.assertIn("pillar_p3_antipattern_catalog", blocking_ids)
        self.assertIn("pillar_p4_triager_model", blocking_ids)

    def test_p1_audited_primary_route_closes_quality_gate(self) -> None:
        mod = load_module()
        write_json(
            self.root / "audit" / "corpus_tags" / "derived" / "invariant_library_index.json",
            {
                "schema_version": "auditooor.invariant_library_index.v1",
                "total_invariants": 502,
            },
        )
        write_json(
            self.root / "reports" / "p1" / "library_quality_audit.json",
            {
                "schema_version": "auditooor.p1_library_quality_audit.v1",
                "overall_tp_rate_pct": 50.0,
                "tp_rate_threshold_pct": 60.0,
                "library_verdict": "P1-LIBRARY-TEMPLATE-HEAVY",
            },
        )
        write(
            self.root / "audit" / "corpus_tags" / "derived" / "invariants_pilot_audited.jsonl",
            "".join(json.dumps({"invariant_id": f"INV-AUD-{i:03d}"}) + "\n" for i in range(52)),
        )
        write(
            self.root / "tools" / "vault-mcp-server.py",
            'quality_mode = "audited_primary"\npath = "invariants_pilot_audited.jsonl"\n',
        )
        write(
            self.root / "tools" / "dispatch-agent-with-prebriefing.py",
            'call_local_mcp_tool("vault_invariant_library", {"quality_mode": "audited_primary"})\n',
        )
        write(
            self.root / "tools" / "live-target-intelligence-report.py",
            'audited = "invariants_pilot_audited.jsonl"\nbreadth_paths = []\n',
        )
        write(
            self.root / "tools" / "invariant-grounded-finding-check.py",
            'DEFAULT_PILOT_AUDITED = "invariants_pilot_audited.jsonl"\n'
            'cited_audited_invariant_ids = []\n',
        )
        write(
            self.root / "tools" / "p1-candidate-triage-dogfood.py",
            'DEFAULT_AUDITED_PRIMARY = "invariants_pilot_audited.jsonl"\n'
            "include_extracted = False\n"
            'broad_extracted_policy = "opt_in_only"\n',
        )

        evidence = mod._pillar_p1_evidence(self.root)

        self.assertEqual(evidence["status"], "met")
        self.assertTrue(evidence["quality_gate"]["met"])
        self.assertFalse(evidence["quality_gate"]["broad_quality_met"])
        audited = evidence["quality_gate"]["audited_primary"]
        self.assertTrue(audited["met"])
        self.assertEqual(audited["retained_rows"], 52)
        self.assertTrue(all(audited["routing_hits"].values()))
        self.assertIn("audited-primary route closed", evidence["reason"])

    def test_p1_surfaces_llm_sweep_gate_without_promoting_quality(self) -> None:
        mod = load_module()
        write_json(
            self.root / "audit" / "corpus_tags" / "derived" / "invariant_library_index.json",
            {"schema_version": "auditooor.invariant_library_index.v1", "total_invariants": 500},
        )
        write(
            self.root / "tools" / "llm-sweep-invariants-mvp.py",
            "MIN_PROMOTION_Y_RATE = 0.90\n"
            "def evaluate_paid_sweep_gate():\n"
            "    return evaluate_spot_check_gate(disallow_template_or_broad=True)\n",
        )

        evidence = mod._pillar_p1_evidence(self.root)
        llm_sweep = evidence["quality_gate"]["llm_sweep"]

        self.assertEqual(evidence["status"], "partial")
        self.assertTrue(llm_sweep["gate_markers_present"])
        self.assertFalse(llm_sweep["met"])
        self.assertEqual(llm_sweep["status"], "gate_implemented_not_promoted")

    def test_p1_llm_sweep_prefers_full_library_artifacts_without_fallback_overclaim(self) -> None:
        mod = load_module()
        write(
            self.root / "tools" / "llm-sweep-invariants-mvp.py",
            "MIN_PROMOTION_Y_RATE = 0.90\n"
            "def evaluate_paid_sweep_gate():\n"
            "    return evaluate_spot_check_gate(disallow_template_or_broad=True)\n",
        )
        write(
            self.root / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl",
            "".join(json.dumps({"invariant_id": f"INV-OLD-{i:03d}"}) + "\n" for i in range(400)),
        )
        write(
            self.root / "audit" / "corpus_tags" / "derived" / "invariants_extracted_llm_v1.jsonl",
            "".join(json.dumps({"invariant_id": f"INV-OLD-{i:03d}"}) + "\n" for i in range(400)),
        )
        write(
            self.root / "reports" / "v3_iter_2026-05-24" / "lane_P1_LLM_SWEEP_MVP" / "sweep_log.jsonl",
            "".join(json.dumps({"status": "ok"}) + "\n" for _ in range(400)),
        )
        write(
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P1_LLM_SWEEP_MVP"
            / "p1_full_library_sweep_input.jsonl",
            "".join(json.dumps({"invariant_id": f"INV-FULL-{i:03d}"}) + "\n" for i in range(500)),
        )
        write_json(
            self.root / "reports" / "v3_iter_2026-05-24" / "lane_P1_LLM_SWEEP_MVP" / "sweep_summary.json",
            {
                "coverage_scope": "full_library",
                "promotion_allowed": True,
                "min_promotion_y_rate": 0.9,
                "after_spot_check": {"y_rate": 1.0, "template_or_broad_count": 0},
            },
        )
        write_json(
            self.root / "reports" / "v3_iter_2026-05-24" / "lane_P1_LLM_SWEEP_MVP" / "sweep_status.json",
            {"coverage_scope": "full_library", "live_sweep_completed": True},
        )

        evidence = mod._p1_llm_sweep_quality_evidence(self.root)

        self.assertEqual(evidence["coverage_scope"], "full_library")
        self.assertEqual(evidence["input_records"], 500)
        self.assertEqual(evidence["output_records"], 0)
        self.assertEqual(evidence["log_records"], 0)
        self.assertFalse(evidence["met"])
        self.assertEqual(evidence["status"], "gate_implemented_not_promoted")

    def test_p1_llm_sweep_promotes_full_library_from_summary_and_status(self) -> None:
        mod = load_module()
        lane = self.root / "reports" / "v3_iter_2026-05-24" / "lane_P1_LLM_SWEEP_MVP"
        write(
            self.root / "tools" / "llm-sweep-invariants-mvp.py",
            "MIN_PROMOTION_Y_RATE = 0.90\n"
            "def evaluate_paid_sweep_gate():\n"
            "    return evaluate_spot_check_gate(disallow_template_or_broad=True)\n",
        )
        write(
            lane / "p1_full_library_sweep_input.jsonl",
            "".join(json.dumps({"invariant_id": f"INV-FULL-{i:03d}"}) + "\n" for i in range(3)),
        )
        write(
            self.root / "audit" / "corpus_tags" / "derived" / "invariants_full_library_llm_v1.jsonl",
            "".join(json.dumps({"invariant_id": f"INV-FULL-{i:03d}"}) + "\n" for i in range(3)),
        )
        write(
            lane / "sweep_log_full_library.jsonl",
            "".join(json.dumps({"invariant_id": f"INV-FULL-{i:03d}", "status": "ok"}) + "\n" for i in range(3)),
        )
        write_json(
            lane / "sweep_summary.json",
            {
                "coverage_scope": "full_library",
                "promotion_allowed": True,
                "min_promotion_y_rate": 0.9,
                "after_spot_check": {
                    "y_rate": 0.95,
                    "promotion_allowed": True,
                    "template_or_broad_count": 0,
                },
            },
        )
        write_json(lane / "sweep_status.json", {"coverage_scope": "full_library", "status": "completed"})

        evidence = mod._p1_llm_sweep_quality_evidence(self.root)

        self.assertEqual(evidence["coverage_scope"], "full_library")
        self.assertEqual(evidence["input_records"], 3)
        self.assertEqual(evidence["output_records"], 3)
        self.assertEqual(evidence["log_records"], 3)
        self.assertTrue(evidence["summary_promotion_allowed"])
        self.assertTrue(evidence["status_live_completed"])
        self.assertTrue(evidence["met"])
        self.assertEqual(evidence["status"], "passed")

    def test_p2_causal_chain_mvp_sample_counts_as_partial_not_met(self) -> None:
        mod = load_module()
        write(self.root / "tools" / "causal-chain-extract.py", "# fixture\n")
        write(
            self.root / "reports" / "v3_iter_2026-05-24" / "lane_V3_P2_CAUSAL_CHAIN_MVP" / "causal_chains_sample.jsonl",
            "".join(json.dumps({"chain_id": f"sample-{i}"}) + "\n" for i in range(25)),
        )
        write_json(
            self.root / "reports" / "v3_iter_2026-05-24" / "lane_V3_P2_CAUSAL_CHAIN_MVP" / "index.json",
            {"schema_version": "auditooor.causal_chain.v1.index", "row_count": 25},
        )

        report = mod.build_report(self.root)

        p2 = report["categories"]["pillar_p2_causal_chains"]
        self.assertEqual(p2["status"], "partial")
        self.assertEqual(p2["observed_records"], 0)
        self.assertEqual(p2["sample_records"], 25)
        self.assertIn("full promoted corpus index is not closed", p2["reason"])
        blocking_ids = {row["category_id"] for row in report["blocking_unmet_categories"]}
        self.assertIn("pillar_p2_causal_chains", blocking_ids)

    def test_p2_canonical_count_without_quality_gate_stays_partial(self) -> None:
        mod = load_module()
        write(self.root / "tools" / "causal-chain-extract.py", "# fixture\n")
        write(
            self.root / "audit" / "corpus_tags" / "derived" / "causal_chains.jsonl",
            "".join(json.dumps({"chain_id": f"CHAIN-{i:03d}"}) + "\n" for i in range(100)),
        )
        write_json(
            self.root / "audit" / "corpus_tags" / "derived" / "causal_chain_index.json",
            {"schema": "auditooor.causal_chain_index.v1", "row_count": 100},
        )

        report = mod.build_report(self.root)
        p2 = report["categories"]["pillar_p2_causal_chains"]
        self.assertEqual(p2["status"], "partial")
        self.assertIn("quality gate is not closed", p2["reason"])

    def test_p2_stale_canonical_quality_gate_stays_partial(self) -> None:
        mod = load_module()
        write(self.root / "tools" / "causal-chain-extract.py", "# fixture\n")
        write_json(
            self.root / "audit" / "corpus_tags" / "derived" / "causal_chain_index.json",
            {
                "schema": "auditooor.causal_chain_index.v1",
                "row_count": 120,
                "quality_gate": {
                    "profile": "canonical",
                    "accepted_rows": 120,
                    "target_records": 100,
                    "met": True,
                    "requirements": [
                        "verification_tier != unknown",
                        "preconditions non-empty",
                        "preconditions exclude placeholder tbd/todo",
                    ],
                },
            },
        )

        report = mod.build_report(self.root)
        p2 = report["categories"]["pillar_p2_causal_chains"]

        self.assertEqual(p2["status"], "partial")
        self.assertFalse(p2["quality_gate_current_requirements_met"])
        self.assertEqual(
            p2["quality_gate_missing_requirements"],
            ["defense must not be fallback/placeholder"],
        )
        self.assertIn("quality gate is stale", p2["reason"])

    def test_p2_prefers_latest_current_quality_gate_artifact(self) -> None:
        mod = load_module()
        write(self.root / "tools" / "causal-chain-extract.py", "# fixture\n")
        write_json(
            self.root / "audit" / "corpus_tags" / "derived" / "causal_chain_index.json",
            {
                "schema": "auditooor.causal_chain_index.v1",
                "row_count": 36093,
                "quality_gate": {
                    "profile": "canonical",
                    "accepted_rows": 36093,
                    "target_records": 100,
                    "met": True,
                    "requirements": [
                        "verification_tier != unknown",
                        "preconditions non-empty",
                        "preconditions exclude placeholder tbd/todo",
                    ],
                },
            },
        )
        latest_index = (
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_FULL_VALIDATION_MATRIX"
            / "raw"
            / "causal_chain_index.canonical.json"
        )
        write_json(
            latest_index,
            {
                "schema": "auditooor.causal_chain_index.v1",
                "row_count": 2610,
                "quality_gate": {
                    "profile": "canonical",
                    "accepted_rows": 2610,
                    "target_records": 100,
                    "met": True,
                    "requirements": list(mod.P2_CANONICAL_QUALITY_REQUIREMENTS),
                    "rejected_by_reason": {"defense_fallback_or_placeholder": 45758},
                },
            },
        )

        report = mod.build_report(self.root)
        p2 = report["categories"]["pillar_p2_causal_chains"]

        self.assertEqual(p2["status"], "met")
        self.assertEqual(p2["observed_records"], 2610)
        self.assertTrue(p2["quality_gate_current_requirements_met"])
        self.assertEqual(p2["quality_gate_missing_requirements"], [])
        self.assertEqual(
            p2["selected_index_ref"],
            "reports/v3_iter_2026-05-24/lane_FULL_VALIDATION_MATRIX/raw/causal_chain_index.canonical.json",
        )
        self.assertIn("current quality gate closed", p2["reason"])

    def test_p3_command_plan_rows_are_met_but_reported_as_degraded(self) -> None:
        mod = load_module()
        for i in range(127):
            write(
                self.root / "obsidian-vault" / "anti-patterns" / "v2" / "solidity" / f"g{i:03d}.yaml",
                "schema_version: auditooor.antipattern_catalog.v1\n"
                f"pattern_id: solidity.g{i:03d}\n"
                "language: solidity\n"
                "query_type: grep\n",
            )
        samples = {
            "semgrep": "solidity.semgrep-sample",
            "ast": "go.ast-sample",
            "tree-sitter": "rust.tree-sitter-sample",
        }
        for query_type, pattern_id in samples.items():
            language = pattern_id.split(".", 1)[0]
            write(
                self.root / "obsidian-vault" / "anti-patterns" / "v2" / language / f"{query_type}.yaml",
                "schema_version: auditooor.antipattern_catalog.v1\n"
                f"pattern_id: {pattern_id}\n"
                f"language: {language}\n"
                f"query_type: {query_type}\n",
            )
        write(
            self.root / "tools" / "antipattern-catalog-build.py",
            "SEMANTIC_COMMAND_PLAN_QUERY_TYPES = {'semgrep', 'ast', 'tree-sitter'}\n"
            "query_degraded = True\n"
            "command_plan = True\n",
        )

        report = mod.build_report(self.root)
        p3 = report["categories"]["pillar_p3_antipattern_catalog"]

        self.assertEqual(p3["status"], "met")
        self.assertEqual(p3["observed_records"], 130)
        self.assertEqual(p3["total_catalog_records"], 130)
        self.assertEqual(p3["executable_query_records"], 127)
        self.assertEqual(p3["degraded_command_plan_records"], 3)
        self.assertEqual(p3["semantic_command_plan_records"], 3)
        self.assertEqual(p3["unsupported_query_records"], 0)
        self.assertEqual(p3["query_execution_status"], "degraded_command_plan")
        self.assertIn("degraded command-plan adapters", p3["reason"])

    def test_p4_reports_provider_blocked_only_with_concrete_evidence(self) -> None:
        mod = load_module()
        write(self.root / "reference" / "triager_patterns.json", "[]\n")
        write(self.root / "tools" / "lib" / "triager_precheck_schema.py", "# fixture\n")
        write(self.root / "tools" / "triager-pre-filing-simulator.py", "# fixture\n")
        write(self.root / "tools" / "vault-mcp-server.py", "vault_live_target_report\n")
        write_json(
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_V3_REMAINING_P4_TRIAGER_MODEL"
            / "provider_prereq_resolution.json",
            {
                "p4_can_run_now": False,
                "provider_auth": {
                    "kimi": {"usable_dry_run": True, "usable_live_smoke": False, "live_smoke_error_class": "http-4xx"},
                    "minimax": {"usable_dry_run": False},
                },
                "local_dependency_blockers": [{"blocker": "missing scikit-learn"}],
                "network_consent": {
                    "required_for_live_calls": True,
                    "AUDITOOOR_LLM_NETWORK_CONSENT": False,
                    "ADVERSARIAL_LIVE_CONSENT": False,
                },
            },
        )

        report = mod.build_report(self.root)
        p4 = report["categories"]["pillar_p4_triager_model"]
        self.assertEqual(p4["status"], "partial")
        self.assertFalse(p4["provider_backed_simulator_present"])
        self.assertTrue(p4["provider_backed_blocked"])
        self.assertGreaterEqual(len(p4["provider_backed_blockers"]), 1)
        self.assertIn("kimi_live_smoke_http-4xx", p4["provider_backed_blockers"])
        self.assertTrue(p4["provider_backed_readiness"]["blocked"])
        self.assertFalse(p4["provider_backed_readiness"]["ready"])
        self.assertFalse(p4["local_mind_model_evidence"]["rules_mcp_present"])

    def test_p4_local_rules_mcp_met_without_provider_backed_overclaim(self) -> None:
        mod = load_module()
        write(self.root / "reference" / "triager_patterns.json", "[]\n")
        write(self.root / "tools" / "lib" / "triager_precheck_schema.py", "# fixture\n")
        write(
            self.root / "tools" / "triager-pre-filing-simulator.py",
            'CAPABILITIES = {"provider_backed_simulation": False}\n',
        )
        write(
            self.root / "tools" / "vault-mcp-server.py",
            'vault_triager_precheck_rules\n'
            'vault_triager_simulate\n'
            'provider_status["provider_backed"] = False\n',
        )
        write_json(
            self.root / "reports" / "p4" / "provider_prereq_resolution.json",
            {
                "p4_can_run_now": False,
                "provider_auth": {"minimax": {"usable_dry_run": False}},
                "network_consent": {
                    "required_for_live_calls": True,
                    "AUDITOOOR_LLM_NETWORK_CONSENT": False,
                    "ADVERSARIAL_LIVE_CONSENT": False,
                },
            },
        )

        report = mod.build_report(self.root)
        p4 = report["categories"]["pillar_p4_triager_model"]

        self.assertEqual(p4["status"], "met")
        self.assertTrue(p4["local_rules_mvp_present"])
        self.assertTrue(p4["local_rules_mcp_present"])
        self.assertTrue(p4["simulate_callable_present"])
        self.assertFalse(p4["provider_backed_simulation_ready"])
        self.assertFalse(p4["provider_backed_simulator_present"])
        self.assertTrue(p4["provider_backed_blocked"])
        self.assertIn("local rules/MCP triager MVP", p4["reason"])
        self.assertIn("provider-backed triager simulation remains blocked", p4["reason"])
        self.assertTrue(p4["local_mind_model_evidence"]["rules_mvp_present"])
        self.assertTrue(p4["local_mind_model_evidence"]["rules_mcp_present"])
        self.assertFalse(p4["provider_backed_readiness"]["ready"])
        self.assertFalse(p4["provider_backed_readiness"]["provider_backed_runnable_now"])

    def test_p4_provider_recheck_summary_keeps_local_and_provider_readiness_separate(self) -> None:
        mod = load_module()
        write(self.root / "reference" / "triager_patterns.json", "[]\n")
        write_json(self.root / "reference" / "triager_disposition_classifier.json", {"schema": "fixture"})
        write(self.root / "tools" / "lib" / "triager_precheck_schema.py", "# fixture\n")
        write(self.root / "tools" / "triager-pre-filing-simulator.py", 'CAPABILITIES = {"provider_backed_simulation": False}\n')
        write(self.root / "tools" / "vault-mcp-server.py", "vault_triager_precheck_rules\nvault_triager_simulate\n")
        write_json(
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P4_PROVIDER_BACKED_RECHECK"
            / "summary.json",
            {
                "schema": "auditooor.p4_provider_backed_recheck.v1",
                "verdict": "provider_backed_simulation_blocked_locally",
                "local_rules_p4_runnable_now": True,
                "provider_backed_p4_runnable_now": False,
                "primary_blockers": [{"blocker": "simulator_has_no_provider_dispatch_boundary"}],
            },
        )

        p4 = mod._pillar_p4_evidence(self.root)

        self.assertEqual(p4["status"], "met")
        self.assertTrue(p4["local_mind_model_evidence"]["classifier_artifact_present"])
        self.assertTrue(p4["provider_backed_readiness"]["local_rules_runnable_now"])
        self.assertFalse(p4["provider_backed_readiness"]["provider_backed_runnable_now"])
        self.assertIn(
            "simulator_has_no_provider_dispatch_boundary",
            p4["provider_backed_readiness"]["blockers"],
        )

    def test_p5_reports_mvp3_exact_sourceproof_artifact_state(self) -> None:
        mod = load_module()
        write(
            self.root / "tools" / "live-target-intelligence-report.py",
            'SCHEMA = "auditooor.live_target_intelligence.v3"\n'
            'TOOL_VERSION = "0.4.1-mvp3-accepted-p1-sourceproof"\n'
            "accepted_p1_source_proof_matches = []\n",
        )
        write(self.root / "tools" / "tests" / "test_live_target_intelligence_report.py", "# fixture\n")
        write(self.root / "tools" / "vault-mcp-server.py", "vault_live_target_report\n")
        write_json(
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P5_ACCEPTED_P1_SOURCEPROOF"
            / "hyperbridge_LIVE_TARGET_REPORT.json",
            {
                "schema": "auditooor.live_target_intelligence.v3",
                "tool_version": "0.4.1-mvp3-accepted-p1-sourceproof",
                "audit_pin": {"report_generated": "2026-05-24T17:39:39Z"},
                "summary_card": {
                    "composability": {
                        "p1_match_tier_counts": {
                            "SEMANTIC-MATCH": 0,
                            "TOPICAL-MATCH": 50,
                            "NO-MATCH": 0,
                        },
                        "p1_semantic_gap_counts": {"topical-only": 50},
                    },
                    "p4_triager_precheck": {
                        "available": True,
                        "state": "completed",
                        "provider_backed": False,
                        "provider_call_made": False,
                        "predicted_verdict_supported": False,
                        "triager_verdict_or_clearance": False,
                        "entries_prechecked": 10,
                        "entries_budget_skipped": 40,
                    },
                },
                "entry_points": [
                    {
                        "accepted_p1_source_proof_matches": [],
                        "p4_triager_precheck": {
                            "provider_status": {
                                "state": "blocked",
                                "provider_backed": False,
                                "provider_call_made": False,
                                "predicted_verdict_supported": False,
                                "blockers": ["live_network_consent_missing"],
                            }
                        },
                    }
                ],
            },
        )

        p5 = mod._pillar_p5_evidence(self.root)

        self.assertEqual(p5["status"], "met")
        self.assertTrue(p5["mvp3_markers_present"])
        self.assertTrue(p5["exact_sourceproof_markers_present"])
        self.assertIn("MVP3 exact-sourceproof", p5["reason"])
        self.assertIn("0/50/0", p5["reason"])
        artifact = p5["current_report_artifact"]
        self.assertTrue(artifact["artifact_present"])
        self.assertEqual(artifact["tool_version"], "0.4.1-mvp3-accepted-p1-sourceproof")
        self.assertEqual(
            artifact["p1_match_tier_counts"],
            {"SEMANTIC-MATCH": 0, "TOPICAL-MATCH": 50, "NO-MATCH": 0},
        )
        self.assertEqual(artifact["topical_only_gap_count"], 50)
        self.assertFalse(artifact["p4_triager_precheck"]["provider_backed"])
        self.assertFalse(artifact["p4_triager_precheck"]["provider_call_made"])
        self.assertEqual(
            artifact["p4_provider_status_sample"]["blockers"],
            ["live_network_consent_missing"],
        )

    def test_p5_mvp3_without_exact_sourceproof_artifact_stays_partial(self) -> None:
        mod = load_module()
        write(
            self.root / "tools" / "live-target-intelligence-report.py",
            'SCHEMA = "auditooor.live_target_intelligence.v3"\n'
            'TOOL_VERSION = "0.4.1-mvp3-accepted-p1-sourceproof"\n'
            "accepted_p1_source_proof_matches = []\n",
        )
        write(self.root / "tools" / "tests" / "test_live_target_intelligence_report.py", "# fixture\n")
        write(self.root / "tools" / "vault-mcp-server.py", "vault_live_target_report\n")
        write_json(
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P5_ACCEPTED_P1_SOURCEPROOF"
            / "hyperbridge_LIVE_TARGET_REPORT.json",
            {
                "schema": "auditooor.live_target_intelligence.v3",
                "tool_version": "0.4.0-mvp3-compose-p4-local",
                "summary_card": {
                    "composability": {
                        "p1_semantic_gap_counts": {"topical-only": "not-int"},
                    },
                    "p4_triager_precheck": {
                        "entries_prechecked": "not-int",
                        "entries_budget_skipped": {},
                    },
                },
                "entry_points": [],
            },
        )

        p5 = mod._pillar_p5_evidence(self.root)

        self.assertEqual(p5["status"], "partial")
        self.assertFalse(p5["exact_sourceproof_ready"])
        self.assertTrue(p5["current_report_artifact"]["artifact_present"])
        self.assertFalse(p5["current_report_artifact"]["exact_sourceproof_artifact"])
        self.assertEqual(p5["current_report_artifact"]["topical_only_gap_count"], 0)
        self.assertEqual(p5["current_report_artifact"]["p4_triager_precheck"]["entries_prechecked"], 0)
        self.assertEqual(p5["current_report_artifact"]["p4_triager_precheck"]["entries_budget_skipped"], 0)

    def test_p5_wrong_sourceproof_version_suffix_stays_partial(self) -> None:
        mod = load_module()
        wrong_version = "0.4.1-mvp3-accepted-p1-sourceproof-suffix"
        write(
            self.root / "tools" / "live-target-intelligence-report.py",
            'SCHEMA = "auditooor.live_target_intelligence.v3"\n'
            f'TOOL_VERSION = "{wrong_version}"\n'
            "accepted_p1_source_proof_matches = []\n",
        )
        write(self.root / "tools" / "tests" / "test_live_target_intelligence_report.py", "# fixture\n")
        write(self.root / "tools" / "vault-mcp-server.py", "vault_live_target_report\n")
        write_json(
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P5_ACCEPTED_P1_SOURCEPROOF"
            / "hyperbridge_LIVE_TARGET_REPORT.json",
            {
                "schema": "auditooor.live_target_intelligence.v3",
                "tool_version": wrong_version,
                "summary_card": {
                    "composability": {
                        "p1_match_tier_counts": {
                            "SEMANTIC-MATCH": 0,
                            "TOPICAL-MATCH": 50,
                            "NO-MATCH": 0,
                        }
                    }
                },
                "entry_points": [{"accepted_p1_source_proof_matches": []}],
            },
        )

        p5 = mod._pillar_p5_evidence(self.root)

        self.assertEqual(p5["status"], "partial")
        self.assertFalse(p5["tool_sourceproof_version_present"])
        self.assertFalse(p5["exact_sourceproof_ready"])
        self.assertFalse(p5["current_report_artifact"]["exact_sourceproof_artifact"])

    def test_complete_like_fixture_keeps_partial_when_keep_rows_pending(self) -> None:
        mod = load_module()
        self.seed_common_tools_and_targets()
        write(self.root / "tools" / "agent-artifact-miner.py", "# lesson source miner\n")
        write(self.root / "tools" / "external-intel-refresh.py", "# source miner\n")
        write(self.root / "tools" / "hackerman-etl-from-post-mortem.py", "# source miner\n")
        write(self.root / "tools" / "solodit-rest-direct.py", "# source miner\n")

        write_json(
            self.root / ".auditooor" / "audit_workflow_coverage_map.json",
            {
                "schema": "auditooor.audit_workflow_coverage_map.v1",
                "workflows": [
                    {
                        "workflow_id": "audit",
                        "concepts": [
                            {"concept_id": "mcp_recall", "status": "present"},
                            {"concept_id": "provider_fanout", "status": "present"},
                        ],
                    }
                ],
            },
        )
        write_json(
            self.root / ".auditooor" / "mining_coverage_dashboard.json",
            {
                "schema": "auditooor.mining_coverage_dashboard.v1",
                "summary": {"total_sources": 6, "fresh": 6, "stale": 0, "missing": 0, "backlog": 0},
            },
        )
        write_json(
            self.root / ".auditooor" / "field_validation_report.json",
            {
                "schema": "auditooor.field_validation_report.v1",
                "readiness": {
                    "status": "field_validation_ready_for_evaluation",
                    "ready_sections": 3,
                    "blocking_unknowns": [],
                },
            },
        )
        write_json(
            self.root / ".auditooor" / "hackerman_sidecar_coverage_report.json",
            {
                "schema_version": "auditooor.hackerman_sidecar_coverage_report.v1",
                "blockers": [],
                "corpus": {"active_records": 10, "record_files_seen": 10},
                "sidecars": [
                    {
                        "name": "exploit_predicates",
                        "exists": True,
                        "status": "ok",
                        "canonical_file_coverage_ratio": 1.0,
                    }
                ],
            },
        )
        write_json(self.root / ".auditooor" / "lesson_gate_report.json", {"ok": True})
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "campaign_id": "cam",
                "status": "pass",
                "expected_counts": {"kimi": 1, "minimax": 1},
                "observed_counts": {"run": {"kimi": 1, "minimax": 1}},
                "blockers": [],
            },
        )
        write_json(
            self.root / "audit" / "corpus_tags" / "derived" / "invariant_library_index.json",
            {
                "schema_version": "auditooor.invariant_library_index.v1",
                "total_invariants": 500,
            },
        )
        write_json(
            self.root / "reports" / "p1" / "library_quality_audit.json",
            {
                "schema_version": "auditooor.p1_library_quality_audit.v1",
                "overall_tp_rate_pct": 80.0,
                "tp_rate_threshold_pct": 60.0,
                "library_verdict": "P1-LIBRARY-USEFUL",
            },
        )
        write(
            self.root / "audit" / "corpus_tags" / "derived" / "causal_chains.jsonl",
            "".join(json.dumps({"chain_id": f"CHAIN-{i:03d}"}) + "\n" for i in range(100)),
        )
        write_json(
            self.root / "audit" / "corpus_tags" / "derived" / "causal_chain_index.json",
            {
                "schema": "auditooor.causal_chain_index.v1",
                "row_count": 100,
                "quality_gate": {
                    "profile": "canonical",
                    "accepted_rows": 100,
                    "target_records": 100,
                    "met": True,
                    "requirements": list(mod.P2_CANONICAL_QUALITY_REQUIREMENTS),
                },
            },
        )
        write(self.root / "tools" / "causal-chain-extract.py", "# fixture\n")
        for i in range(130):
            write(
                self.root / "obsidian-vault" / "anti-patterns" / "v2" / "solidity" / f"p{i:03d}.yaml",
                "schema_version: auditooor.antipattern_catalog.v1\n"
                f"pattern_id: solidity.p{i:03d}\n"
                "language: solidity\n"
                "query_type: grep\n",
            )
        write(self.root / "tools" / "antipattern-catalog-build.py", "# fixture\n")
        write(self.root / "reference" / "triager_patterns.json", "[]\n")
        write(self.root / "tools" / "lib" / "triager_precheck_schema.py", "# fixture\n")
        write(self.root / "tools" / "triager-pre-filing-simulator.py", "# fixture\n")
        write(self.root / "tools" / "vault-mcp-server.py", "vault_live_target_report\nvault_triager_simulate\n")
        write(
            self.root / "tools" / "live-target-intelligence-report.py",
            'SCHEMA = "auditooor.live_target_intelligence.v3"\n'
            'TOOL_VERSION = "0.4.1-mvp3-accepted-p1-sourceproof"\n'
            "accepted_p1_source_proof_matches = []\n",
        )
        write(self.root / "tools" / "tests" / "test_live_target_intelligence_report.py", "# fixture\n")
        write_json(
            self.root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P5_ACCEPTED_P1_SOURCEPROOF"
            / "hyperbridge_LIVE_TARGET_REPORT.json",
            {
                "schema": "auditooor.live_target_intelligence.v3",
                "tool_version": "0.4.1-mvp3-accepted-p1-sourceproof",
                "summary_card": {
                    "composability": {
                        "p1_match_tier_counts": {
                            "SEMANTIC-MATCH": 0,
                            "TOPICAL-MATCH": 50,
                            "NO-MATCH": 0,
                        },
                        "p1_semantic_gap_counts": {"topical-only": 50},
                    },
                    "p4_triager_precheck": {"provider_backed": False},
                },
                "entry_points": [{"accepted_p1_source_proof_matches": []}],
            },
        )
        write_json(self.root / "reports" / "field_validation_real_hunt.json", {"submitted": True})
        write_json(
            self.root / "agent_outputs" / "llm_dispatch_a.json",
            {"provider": "kimi", "outcome": "success"},
        )
        write(
            self.root / "tools" / "calibration" / "llm_budget_log.jsonl",
            "".join(json.dumps({"provider": "kimi", "success": True}) + "\n" for _ in range(10)),
        )
        write(
            self.root / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        write_json(
            self.root / ".auditooor" / "provider_fanout" / "local_verification_queue.json",
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {
                        "verification_status": "pending",
                        "local_verification_required": True,
                        "source_collection_required": False,
                        "terminal_judgment_required": False,
                    }
                ],
            },
        )

        report = mod.build_report(self.root)

        self.assertEqual(report["categories"]["field_validation"]["status"], "met")
        self.assertEqual(report["categories"]["source_miners"]["status"], "met")
        self.assertEqual(report["categories"]["lesson_gates"]["status"], "met")
        self.assertEqual(report["categories"]["real_hunt_validation"]["status"], "met")
        self.assertEqual(report["categories"]["provider_campaign_completeness"]["status"], "met")
        self.assertEqual(report["categories"]["provider_keep_verification"]["status"], "partial")
        self.assertEqual(
            report["categories"]["provider_keep_verification"]["verification_status_counts"],
            {"pending": 1},
        )
        self.assertEqual(report["categories"]["provider_keep_verification"]["backfill_packet_pending_rows"], 0)
        blocking_ids = {row["category_id"] for row in report["blocking_unmet_categories"]}
        self.assertEqual(blocking_ids, {"provider_keep_verification"})

    def test_mining_dashboard_keeps_queued_sources_partial(self) -> None:
        mod = load_module()
        self.seed_common_tools_and_targets()
        write(self.root / "tools" / "external-intel-refresh.py", "# source miner\n")
        write(self.root / "tools" / "solodit-rest-direct.py", "# source miner\n")
        write_json(
            self.root / ".auditooor" / "mining_coverage_dashboard.json",
            {
                "schema": "auditooor.mining_coverage_dashboard.v1",
                "summary": {"total_sources": 3, "fresh": 1, "queued": 2, "stale": 0, "missing": 0, "backlog": 0},
            },
        )

        report = mod.build_report(self.root)

        self.assertEqual(report["categories"]["mining_dashboard"]["status"], "partial")
        self.assertEqual(report["categories"]["source_miners"]["status"], "partial")
        self.assertIn("queued=2", report["categories"]["mining_dashboard"]["reason"])

    def test_provider_campaign_pass_is_partial_when_live_provider_blocker_active(self) -> None:
        mod = load_module()
        self.seed_common_tools_and_targets()
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "campaign_id": "historical-campaign",
                "status": "pass",
                "blockers": [],
            },
        )
        write_json(
            self.root / "reports" / "v3_blocker_ledger" / "blocker_ledger.json",
            {
                "schema": "auditooor.v3_blocker_ledger.v1",
                "blockers": [
                    {
                        "blocker_id": "BLK-V3-PROVIDER-LIVE-DEPENDENCY-NOT-RESTORED",
                        "status": "blocked_missing_model",
                        "external_state_required": True,
                        "next_action": "restore live provider access",
                    }
                ],
            },
        )

        report = mod.build_report(self.root)
        campaign = report["categories"]["provider_campaign_completeness"]

        self.assertEqual(campaign["status"], "partial")
        self.assertIn("fresh live provider fanout remains externally blocked", campaign["reason"])
        self.assertEqual(
            campaign["current_blockers"][0]["blocker_id"],
            "BLK-V3-PROVIDER-LIVE-DEPENDENCY-NOT-RESTORED",
        )
        ledger_summary = report["current_blocker_ledger_summary"]
        self.assertEqual(ledger_summary["status"], "present")
        self.assertEqual(ledger_summary["tracked_total"], 1)
        self.assertEqual(ledger_summary["open_count"], 1)
        self.assertEqual(ledger_summary["external_state_required_open_count"], 1)
        self.assertEqual(ledger_summary["local_actionable_open_count"], 0)
        blocking_ids = {row["category_id"] for row in report["blocking_unmet_categories"]}
        self.assertIn("provider_campaign_completeness", blocking_ids)

    def test_provider_campaign_pass_with_unresolved_rows_stays_partial_despite_advisory_warnings(self) -> None:
        mod = load_module()
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "campaign_id": "cam-with-debt",
                "status": "pass",
                "blockers": [],
                "warnings": [{"kind": "stale_provider_row"}],
                "expected_counts": {"kimi": 2},
                "observed_counts": {"run": {"kimi": 2}},
                "status_counts": {"verified": 1, "pending": 1},
            },
        )

        evidence = mod._provider_campaign_evidence(self.root, None)

        self.assertEqual(evidence["status"], "partial")
        self.assertIn("blocking_warnings=1", evidence["reason"])
        self.assertIn("advisory_warnings=0", evidence["reason"])
        self.assertIn("unresolved_rows=1", evidence["reason"])
        self.assertEqual(evidence["unresolved_status_rows"], 1)

    def test_provider_campaign_pass_with_unknown_warning_stays_partial(self) -> None:
        mod = load_module()
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "campaign_id": "cam-warning-only",
                "status": "pass",
                "blockers": [],
                "warnings": [{"code": "unclassified_provider_warning"}],
                "expected_counts": {"kimi": 2},
                "observed_counts": {"run": {"kimi": 2}},
                "status_counts": {"verified": 2},
            },
        )

        evidence = mod._provider_campaign_evidence(self.root, None)

        self.assertEqual(evidence["status"], "partial")
        self.assertIn("blocking_warnings=1", evidence["reason"])
        self.assertEqual(evidence["blocking_warnings"][0]["code"], "unclassified_provider_warning")

    def test_provider_campaign_broader_results_warning_is_advisory(self) -> None:
        mod = load_module()
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "campaign_id": "single-campaign-pass",
                "status": "pass",
                "blockers": [],
                "warnings": [
                    {
                        "code": "broader_verification_results_excluded",
                        "detail": "broad remediation queues are accounted elsewhere",
                        "excluded_count": 3,
                    }
                ],
                "expected_counts": {"kimi": 2},
                "observed_counts": {"run": {"kimi": 2}},
                "status_counts": {"local_verification": {"verified": 2}},
            },
        )

        evidence = mod._provider_campaign_evidence(self.root, None)

        self.assertEqual(evidence["status"], "met")
        self.assertIn("known warnings are advisory", evidence["reason"])
        self.assertEqual(
            evidence["warnings"][0]["code"],
            "broader_verification_results_excluded",
        )
        self.assertEqual(evidence["blocking_warnings"], [])
        self.assertEqual(evidence["advisory_warning_codes"], ["broader_verification_results_excluded"])

    def test_field_validation_guidance_flows_to_roadmap_blockers(self) -> None:
        mod = load_module()
        self.seed_common_tools_and_targets()
        write_json(
            self.root / ".auditooor" / "field_validation_report.json",
            {
                "schema": "auditooor.field_validation_report.v1",
                "readiness": {
                    "status": "insufficient_needs_more_artifacts",
                    "ready_sections": 1,
                    "blocking_unknowns": ["no exploit queue, execution manifest, or execution bridge artifacts found"],
                    "field_loop_next_steps": [
                        {
                            "artifact": "executed PoC manifest",
                            "expected_paths": ["poc_execution/<candidate-id>/execution_manifest.json"],
                            "next_commands": ["make poc-execution-record WS=/tmp/ws BRIEF=<brief.md>"],
                        }
                    ],
                },
                "signal_groups": {
                    "conversion_proof_execution": {
                        "missing_artifacts": [
                            {
                                "artifact": "executed PoC manifest",
                                "expected_paths": ["poc_execution/<candidate-id>/execution_manifest.json"],
                                "next_commands": ["make poc-execution-record WS=/tmp/ws BRIEF=<brief.md>"],
                            }
                        ],
                        "next_commands": ["make poc-execution-record WS=/tmp/ws BRIEF=<brief.md>"],
                    }
                },
            },
        )

        report = mod.build_report(self.root)

        field = report["categories"]["field_validation"]
        self.assertEqual(field["status"], "partial")
        self.assertEqual(field["missing_artifacts"][0]["artifact"], "executed PoC manifest")
        self.assertEqual(
            field["field_loop_next_steps"][0]["expected_paths"],
            ["poc_execution/<candidate-id>/execution_manifest.json"],
        )
        field_blocker = next(row for row in report["blocking_unmet_categories"] if row["category_id"] == "field_validation")
        self.assertIn("make poc-execution-record", "\n".join(field_blocker["next_commands"]))

    def test_field_validation_ready_status_with_unknowns_stays_partial(self) -> None:
        mod = load_module()
        write_json(
            self.root / ".auditooor" / "field_validation_report.json",
            {
                "schema": "auditooor.field_validation_report.v1",
                "readiness": {
                    "status": "field_validation_ready_for_evaluation",
                    "ready_sections": 3,
                    "blocking_unknowns": ["missing triage outcome linkage"],
                    "field_loop_next_steps": [{"artifact": "workspace/campaign outcome row"}],
                },
                "signal_groups": {},
            },
        )

        evidence = mod._field_validation_evidence(self.root, None)

        self.assertEqual(evidence["status"], "partial")
        self.assertIn("blocking_unknowns=1", evidence["reason"])
        self.assertIn("next_steps=1", evidence["reason"])

    def test_field_validation_reads_platform_id_gap_artifact_for_next_actions(self) -> None:
        mod = load_module()
        write_json(
            self.root / ".auditooor" / "field_validation_report.json",
            {
                "schema": "auditooor.field_validation_report.v1",
                "readiness": {
                    "status": "field_validation_ready_for_evaluation",
                    "ready_sections": 3,
                    "blocking_unknowns": [],
                    "field_loop_next_steps": [],
                },
                "signal_groups": {},
            },
        )
        write_json(
            self.root / "reports" / "field_validation_platform_id_gaps.json",
            {
                "schema": "auditooor.field_validation_platform_id_gaps.v1",
                "counts": {"gap_rows": 2},
                "next_action_rows": [
                    {"action_kind": "record_submission", "command": "make record-submission WS=/tmp/demo ID=<id>"},
                    {"action_kind": "record_outcome", "command": "make record-outcome WS=/tmp/demo ID=<id> STATE=accepted"},
                ],
            },
        )

        evidence = mod._field_validation_evidence(self.root, None)
        report = mod.build_report(self.root)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["platform_id_gap_rows"], 2)
        self.assertIn("platform_id_gap_rows=2", evidence["reason"])
        self.assertIn("record-submission", "\n".join(evidence["next_commands"]))
        self.assertTrue(any("field_validation_platform_id_gaps.json" in ref for ref in evidence["source_refs"]))
        blocker = next(row for row in report["blocking_unmet_categories"] if row["category_id"] == "field_validation")
        self.assertEqual(len(blocker["platform_id_next_action_rows"]), 2)

    def test_field_validation_ignores_different_workspace_latest_gap_artifact(self) -> None:
        mod = load_module()
        write_json(
            self.root / ".auditooor" / "field_validation_report.json",
            {
                "schema": "auditooor.field_validation_report.v1",
                "readiness": {
                    "status": "field_validation_ready_for_evaluation",
                    "ready_sections": 3,
                    "blocking_unknowns": [],
                    "field_loop_next_steps": [],
                },
                "signal_groups": {},
            },
        )
        write_json(
            self.root / "reports" / "v3_iter" / "field_validation_platform_id_gaps.hyperbridge.json",
            {
                "schema": "auditooor.field_validation_platform_id_gaps.v1",
                "workspace": str(self.root / "workspaces" / "hyperbridge"),
                "counts": {"gap_rows": 3},
            },
        )

        evidence = mod._field_validation_evidence(self.root, None)

        self.assertEqual(evidence["status"], "met")
        self.assertEqual(evidence["platform_id_gap_rows"], 0)
        self.assertEqual(evidence["source_refs"], [".auditooor/field_validation_report.json"])

    def test_field_validation_reads_matching_workspace_latest_gap_artifact(self) -> None:
        mod = load_module()
        workspace = self.root / "workspaces" / "hyperbridge"
        write_json(
            workspace / ".auditooor" / "field_validation_report.json",
            {
                "schema": "auditooor.field_validation_report.v1",
                "readiness": {
                    "status": "field_validation_ready_for_evaluation",
                    "ready_sections": 3,
                    "blocking_unknowns": [],
                    "field_loop_next_steps": [],
                },
                "signal_groups": {},
            },
        )
        write_json(
            self.root / "reports" / "v3_iter" / "field_validation_platform_id_gaps.hyperbridge.json",
            {
                "schema": "auditooor.field_validation_platform_id_gaps.v1",
                "workspace": str(workspace),
                "counts": {"gap_rows": 2},
            },
        )

        evidence = mod._field_validation_evidence(self.root, workspace)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["platform_id_gap_rows"], 2)
        self.assertTrue(
            any("field_validation_platform_id_gaps.hyperbridge.json" in ref for ref in evidence["source_refs"])
        )

    def test_field_validation_sanitizes_safe_workspace_command_paths(self) -> None:
        mod = load_module()
        workspace = self.root / "workspaces" / "demo"
        write_json(
            workspace / ".auditooor" / "field_validation_report.json",
            {
                "schema": "auditooor.field_validation_report.v1",
                "readiness": {
                    "status": "insufficient_needs_more_artifacts",
                    "ready_sections": 1,
                    "field_loop_next_steps": [
                        {
                            "artifact": "workspace/campaign outcome row",
                            "expected_paths": [
                                str(workspace / "submissions" / "SUBMISSIONS.md"),
                                str(self.root / "reference" / "outcomes.jsonl"),
                                "/var/tmp/external/outcome.jsonl",
                            ],
                            "next_commands": [
                                f"make record-outcome WS={workspace} ID=<finding-id>",
                                f"make submission-sync WORKSPACE={workspace}",
                                "make external-check WS=/var/tmp/external",
                            ],
                        }
                    ],
                },
                "signal_groups": {
                    "triage_survival": {
                        "missing_artifacts": [
                            {
                                "artifact": "workspace/campaign outcome row",
                                "expected_paths": [str(workspace / "submissions" / "SUBMISSIONS.md")],
                                "next_commands": [f"make record-outcome WS={workspace} ID=<finding-id>"],
                            }
                        ],
                        "next_commands": [f"make record-outcome WS={workspace} ID=<finding-id>"],
                    }
                },
            },
        )

        evidence = mod._field_validation_evidence(self.root, workspace)

        self.assertEqual(evidence["next_commands"], ["make record-outcome WS=<workspace> ID=<finding-id>"])
        self.assertEqual(
            evidence["missing_artifacts"][0]["expected_paths"],
            ["<workspace>/submissions/SUBMISSIONS.md"],
        )
        step = evidence["field_loop_next_steps"][0]
        self.assertEqual(
            step["expected_paths"],
            ["<workspace>/submissions/SUBMISSIONS.md", "reference/outcomes.jsonl", "/var/tmp/external/outcome.jsonl"],
        )
        self.assertEqual(
            step["next_commands"],
            [
                "make record-outcome WS=<workspace> ID=<finding-id>",
                "make submission-sync WORKSPACE=<workspace>",
                "make external-check WS=/var/tmp/external",
            ],
        )

    def test_workspace_source_refs_are_sanitized_outside_repo_root(self) -> None:
        mod = load_module()
        with tempfile.TemporaryDirectory(prefix="workspace outside root ") as workspace_dir:
            workspace = Path(workspace_dir)
            write_json(
                workspace / ".auditooor" / "field_validation_report.json",
                {
                    "schema": "auditooor.field_validation_report.v1",
                    "readiness": {"status": "insufficient_needs_more_artifacts", "ready_sections": 1},
                },
            )
            write_json(
                workspace / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
                {
                    "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                    "campaign_id": "cam",
                    "status": "fail",
                    "blockers": [{"artifact": str(workspace / "artifact.json")}],
                },
            )

            report = mod.build_report(self.root, workspace=workspace)

        self.assertEqual(report["root"], ".")
        self.assertEqual(report["workspace"], "<workspace>")
        self.assertEqual(
            report["categories"]["field_validation"]["source_refs"],
            ["<workspace>/.auditooor/field_validation_report.json"],
        )
        self.assertEqual(
            report["categories"]["provider_campaign_completeness"]["source_refs"],
            ["<workspace>/.auditooor/v3_provider_campaign_completeness_gate.json"],
        )
        provider_blockers = report["categories"]["provider_campaign_completeness"]["blockers"]
        self.assertEqual(provider_blockers[0]["artifact"], "<workspace>/artifact.json")

    def test_workspace_provider_campaign_does_not_use_newer_repo_gate(self) -> None:
        mod = load_module()
        workspace = self.root / "workspaces" / "demo"
        workspace_gate = workspace / ".auditooor" / "v3_provider_campaign_completeness_gate.json"
        repo_gate = self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json"
        write_json(
            workspace_gate,
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "campaign_id": "workspace-campaign",
                "status": "fail",
                "blockers": [{"kind": "missing_minimax"}],
            },
        )
        write_json(
            repo_gate,
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "campaign_id": "repo-campaign",
                "status": "pass",
                "blockers": [],
            },
        )
        os.utime(workspace_gate, (1_700_000_000, 1_700_000_000))
        os.utime(repo_gate, (1_700_000_100, 1_700_000_100))

        report = mod.build_report(self.root, workspace=workspace)
        campaign = report["categories"]["provider_campaign_completeness"]

        self.assertEqual(campaign["status"], "partial")
        self.assertEqual(campaign["campaign_id"], "workspace-campaign")
        self.assertEqual(campaign["source_refs"], ["<workspace>/.auditooor/v3_provider_campaign_completeness_gate.json"])

    def test_real_hunt_scan_does_not_count_field_validation_self_report(self) -> None:
        mod = load_module()
        write_json(
            self.root / "reports" / "field_validation_report.json",
            {"schema": "auditooor.field_validation_report.v1"},
        )
        write_json(
            self.root / "reports" / "field_validation_real_hunt.json",
            {"submitted": True},
        )

        evidence = mod._real_hunt_evidence(self.root, None, {"status": "partial"})

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["source_refs"], ["reports/field_validation_real_hunt.json"])

    def test_source_miners_reads_backlog_actions_and_stays_partial(self) -> None:
        mod = load_module()
        write_json(
            self.root / ".auditooor" / "mining_coverage_dashboard.json",
            {
                "schema": "auditooor.mining_coverage_dashboard.v1",
                "summary": {"total_sources": 1, "fresh_sources": 1, "stale_sources": 0, "missing_sources": 0, "queued_sources": 0},
                "rows": [{"source_id": "s", "status": "fresh"}],
            },
        )
        write_json(
            self.root / "reports" / "source_miner_backlog_actions.json",
            {
                "schema": "auditooor.source_miner_backlog_actions.v1",
                "active_backlog_count": 1,
                "next_action_rows": [{"action_id": "source_miner:solodit:refresh", "command": "python3 tools/solodit-rest-direct.py --plan-language-backlog"}],
            },
        )

        mining = mod._mining_dashboard_evidence(self.root)
        evidence = mod._source_miner_evidence(self.root, mining)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["active_backlog_count"], 1)
        self.assertIn("backlog_actions_active=1", evidence["reason"])
        self.assertEqual(evidence["next_action_rows"][0]["action_id"], "source_miner:solodit:refresh")

    def test_provider_keep_met_when_local_verification_results_have_no_unresolved_rows(self) -> None:
        mod = load_module()
        self.seed_common_tools_and_targets()
        write(
            self.root / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        write_json(
            self.root / ".auditooor" / "provider_fanout" / "v3_provider_local_verification_result.json",
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {
                        "verification_status": "verified",
                        "terminal_outcome": "verified_no_action",
                        "local_verification_required": False,
                        "source_collection_required": False,
                        "terminal_judgment_required": False,
                    }
                ],
            },
        )

        evidence = mod._provider_keep_evidence(self.root)

        self.assertEqual(evidence["status"], "met")
        self.assertEqual(evidence["verification_status_counts"], {"verified": 1})

    def test_provider_keep_reads_custom_v3_fanout_artifacts(self) -> None:
        mod = load_module()
        write(
            self.root / ".auditooor" / "v3_provider_fanout_source_dashboard" / "runs" / "live" / "provider_outputs" / "kimi.out.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        write_json(
            self.root / ".auditooor" / "v3_provider_fanout_source_dashboard" / "runs" / "live" / "v3_provider_local_verification_result.json",
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {
                        "verification_status": "verified",
                        "local_verification_required": False,
                        "source_collection_required": False,
                        "terminal_judgment_required": True,
                    }
                ],
            },
        )

        evidence = mod._provider_keep_evidence(self.root)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["keep_mentions"], 1)
        self.assertEqual(evidence["verification_status_counts"], {"verified": 1})
        self.assertEqual(evidence["terminal_judgment_required_rows"], 1)
        self.assertEqual(
            evidence["local_verification_artifacts"][0],
            ".auditooor/v3_provider_fanout_source_dashboard/runs/live/v3_provider_local_verification_result.json",
        )

    def test_provider_keep_counts_backfill_packets_and_legacy_needs_more_source(self) -> None:
        mod = load_module()
        write(
            self.root / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        write_json(
            self.root / ".auditooor" / "provider_keep_verification_backfill.json",
            {
                "schema": "auditooor.provider_keep_verification_backfill.v1",
                "packets": [{"packet_id": "KEEP-BACKFILL-001"}],
            },
        )
        write_json(
            self.root / ".auditooor" / "provider_fanout" / "v3_provider_local_verification_result.json",
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {
                        "verification_status": "needs_more_source",
                        "terminal_outcome": "needs_more_source",
                    }
                ],
            },
        )

        evidence = mod._provider_keep_evidence(self.root)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["backfill_packet_pending_rows"], 1)
        self.assertEqual(evidence["source_collection_required_rows"], 1)

    def test_provider_keep_backfill_result_replaces_packet_pending_count(self) -> None:
        mod = load_module()
        write(
            self.root / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        write_json(
            self.root / ".auditooor" / "provider_keep_verification_backfill.json",
            {
                "schema": "auditooor.provider_keep_verification_backfill.v1",
                "packets": [{"packet_id": "KEEP-BACKFILL-001"}, {"packet_id": "KEEP-BACKFILL-002"}],
            },
        )
        write_json(
            self.root / ".auditooor" / "provider_keep_verification_backfill_result.json",
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {
                        "verification_status": "needs_more_source",
                        "terminal_outcome": "needs_more_source",
                        "source_collection_required": True,
                    },
                    {
                        "verification_status": "verified",
                        "terminal_judgment_required": True,
                    },
                ],
            },
        )

        evidence = mod._provider_keep_evidence(self.root)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["backfill_packet_total_rows"], 2)
        self.assertEqual(evidence["backfill_result_rows"], 2)
        self.assertEqual(evidence["backfill_packet_pending_rows"], 0)
        self.assertEqual(evidence["source_collection_required_rows"], 1)
        self.assertEqual(evidence["terminal_judgment_required_rows"], 1)
        self.assertEqual(evidence["verification_status_counts"], {"needs_more_source": 1, "verified": 1})

    def test_provider_keep_surfaces_closure_queue_without_closing_unresolved_rows(self) -> None:
        mod = load_module()
        write(
            self.root / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        write_json(
            self.root / ".auditooor" / "provider_fanout" / "v3_provider_local_verification_result.json",
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {
                        "verification_status": "needs_more_source",
                        "terminal_outcome": "needs_more_source",
                        "source_collection_required": True,
                    },
                    {
                        "verification_status": "verified",
                        "terminal_judgment_required": True,
                    },
                ],
            },
        )
        write_json(
            self.root / ".auditooor" / "provider_closure_packet_queue.json",
            {
                "schema": "auditooor.v3_provider_source_collection_queue.v1",
                "summary": {
                    "source_rows": 1,
                    "deduped_items": 1,
                    "terminal_judgment_rows": 1,
                    "terminal_judgment_items": 1,
                    "by_family": {"solodit": 1},
                    "by_terminal_family": {"kill_review": 1},
                },
            },
        )

        evidence = mod._provider_keep_evidence(self.root)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["source_collection_required_rows"], 1)
        self.assertEqual(evidence["terminal_judgment_required_rows"], 1)
        self.assertEqual(evidence["closure_packet_queue"]["deduped_items"], 1)
        self.assertEqual(evidence["closure_packet_queue"]["terminal_judgment_items"], 1)
        self.assertIn("Remediation routing evidence only", evidence["closure_packet_queue"]["claim_guard"])

    def test_provider_keep_uses_selected_campaign_verification_not_historical_blockers(self) -> None:
        mod = load_module()
        write(
            self.root / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        historical_rows = [
            {"verification_status": "needs_more_source", "source_collection_required": True}
            for _ in range(50)
        ]
        write_json(
            self.root / ".auditooor" / "provider_fanout" / "old" / "v3_provider_local_verification_result.json",
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": historical_rows,
            },
        )
        selected_path = (
            self.root
            / ".auditooor"
            / "provider_fanout"
            / "current"
            / "v3_provider_local_verification_result.json"
        )
        write_json(
            selected_path,
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {"verification_status": "needs_more_source", "source_collection_required": True},
                    {"verification_status": "needs_more_source", "source_collection_required": True},
                    {"verification_status": "needs_more_source", "source_collection_required": True},
                ],
            },
        )
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "status": "fail",
                "artifacts": {"local_verification": str(selected_path)},
            },
        )

        evidence = mod._provider_keep_evidence(self.root)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["verification_status_counts"], {"needs_more_source": 3})
        self.assertEqual(evidence["source_collection_required_rows"], 3)
        self.assertEqual(evidence["unresolved_rows"], 3)
        self.assertEqual(evidence["historical_local_verification_artifacts"]["verification_status_counts"], {"needs_more_source": 53})
        self.assertEqual(evidence["historical_local_verification_artifacts"]["unresolved_rows"], 53)
        self.assertEqual(
            evidence["selected_local_verification_artifacts"],
            [".auditooor/provider_fanout/current/v3_provider_local_verification_result.json"],
        )

    def test_provider_keep_marks_closure_queue_stale_against_selected_verification(self) -> None:
        mod = load_module()
        write(
            self.root / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        selected_path = (
            self.root
            / ".auditooor"
            / "provider_fanout"
            / "current"
            / "v3_provider_local_verification_result.json"
        )
        write_json(
            selected_path,
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {"verification_status": "needs_more_source", "source_collection_required": True},
                ],
            },
        )
        queue_path = self.root / ".auditooor" / "provider_closure_packet_queue.json"
        write_json(
            queue_path,
            {
                "schema": "auditooor.v3_provider_source_collection_queue.v1",
                "summary": {"source_rows": 29, "deduped_items": 4},
            },
        )
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "status": "fail",
                "artifacts": {"local_verification": str(selected_path)},
            },
        )
        os.utime(queue_path, (1_700_000_000, 1_700_000_000))
        os.utime(selected_path, (1_700_000_100, 1_700_000_100))

        evidence = mod._provider_keep_evidence(self.root)

        self.assertTrue(evidence["closure_packet_queue"]["stale"])
        self.assertEqual(
            evidence["closure_packet_queue"]["selected_local_verification_ref"],
            ".auditooor/provider_fanout/current/v3_provider_local_verification_result.json",
        )

    def test_provider_keep_selected_clean_result_ignores_stale_backfill_packets(self) -> None:
        mod = load_module()
        write(
            self.root / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        selected_path = (
            self.root
            / ".auditooor"
            / "provider_fanout"
            / "current"
            / "v3_provider_local_verification_result.json"
        )
        write_json(
            selected_path,
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {
                        "verification_status": "verified",
                        "terminal_outcome": "verified_no_action",
                    }
                ],
            },
        )
        write_json(
            self.root / ".auditooor" / "provider_keep_verification_backfill.json",
            {
                "schema": "auditooor.provider_keep_verification_backfill.v1",
                "packets": [{"packet_id": "STALE-001"}, {"packet_id": "STALE-002"}],
            },
        )
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "status": "pass",
                "artifacts": {"local_verification": str(selected_path)},
            },
        )

        evidence = mod._provider_keep_evidence(self.root)

        self.assertEqual(evidence["status"], "met")
        self.assertEqual(evidence["verification_status_counts"], {"verified": 1})
        self.assertEqual(evidence["backfill_packet_pending_rows"], 0)
        self.assertEqual(evidence["backfill_packet_total_rows"], 2)

    def test_provider_keep_resolves_sanitized_workspace_selected_artifact(self) -> None:
        mod = load_module()
        workspace = self.root / "workspaces" / "demo"
        write(
            workspace / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        selected_path = workspace / ".auditooor" / "provider_fanout" / "current" / "result.json"
        write_json(
            selected_path,
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [
                    {
                        "verification_status": "verified",
                        "terminal_outcome": "verified_no_action",
                    }
                ],
            },
        )
        write_json(
            workspace / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "status": "pass",
                "artifacts": {"local_verification": str(selected_path)},
            },
        )

        campaign = mod._provider_campaign_evidence(self.root, workspace)
        evidence = mod._provider_keep_evidence(self.root, campaign, workspace)

        self.assertEqual(campaign["artifacts"]["local_verification"], "<workspace>/.auditooor/provider_fanout/current/result.json")
        self.assertEqual(evidence["status"], "met")
        self.assertEqual(
            evidence["selected_local_verification_artifacts"],
            ["<workspace>/.auditooor/provider_fanout/current/result.json"],
        )

    def test_workspace_provider_keep_uses_workspace_selected_verification_not_repo_selected_verification(self) -> None:
        mod = load_module()
        workspace = self.root / "workspaces" / "demo"
        repo_selected = self.root / ".auditooor" / "provider_fanout" / "current" / "v3_provider_local_verification_result.json"
        workspace_selected = (
            workspace
            / ".auditooor"
            / "provider_fanout"
            / "current"
            / "v3_provider_local_verification_result.json"
        )
        write(
            workspace / "provider_outputs" / "slice" / "row.txt",
            "classification: KEEP_FOR_LOCAL_VERIFICATION\n",
        )
        write_json(
            repo_selected,
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [{"verification_status": "verified", "terminal_outcome": "verified_no_action"}],
            },
        )
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "status": "pass",
                "artifacts": {"local_verification": str(repo_selected)},
            },
        )
        write_json(
            workspace_selected,
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [{"verification_status": "needs_more_source", "source_collection_required": True}],
            },
        )
        write_json(
            workspace / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "status": "fail",
                "artifacts": {"local_verification": str(workspace_selected)},
            },
        )

        campaign = mod._provider_campaign_evidence(self.root, workspace)
        evidence = mod._provider_keep_evidence(self.root, campaign, workspace)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["verification_status_counts"], {"needs_more_source": 1})
        self.assertEqual(
            evidence["selected_local_verification_artifacts"],
            ["<workspace>/.auditooor/provider_fanout/current/v3_provider_local_verification_result.json"],
        )
        self.assertEqual(evidence["historical_local_verification_artifacts"]["verification_status_counts"], {"needs_more_source": 1})

    def test_workspace_provider_closure_queue_prefers_workspace_scope(self) -> None:
        mod = load_module()
        workspace = self.root / "workspaces" / "demo"
        selected_path = workspace / ".auditooor" / "provider_fanout" / "current" / "result.json"
        write_json(
            selected_path,
            {
                "schema": "auditooor.v3_provider_local_verification_result.v1",
                "rows": [{"verification_status": "needs_more_source", "source_collection_required": True}],
            },
        )
        write_json(
            self.root / ".auditooor" / "provider_closure_packet_queue.json",
            {
                "schema": "auditooor.v3_provider_source_collection_queue.v1",
                "summary": {"source_rows": 99, "deduped_items": 99},
            },
        )
        write_json(
            workspace / ".auditooor" / "provider_closure_packet_queue.json",
            {
                "schema": "auditooor.v3_provider_source_collection_queue.v1",
                "summary": {"source_rows": 1, "deduped_items": 1},
            },
        )

        evidence = mod._provider_closure_packet_queue_evidence(self.root, selected_path, workspace)

        self.assertEqual(evidence["source_rows"], 1)
        self.assertEqual(evidence["deduped_items"], 1)
        self.assertEqual(evidence["source_refs"], ["<workspace>/.auditooor/provider_closure_packet_queue.json"])

    def test_provider_campaign_sanitizes_safe_artifact_and_run_paths(self) -> None:
        mod = load_module()
        write_json(
            self.root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            {
                "schema": "auditooor.v3_provider_campaign_completeness_gate.v1",
                "status": "pass",
                "artifacts": {
                    "local_verification": str(
                        self.root / ".auditooor" / "provider_fanout" / "campaign" / "run" / "result.json"
                    ),
                    "external": "/var/tmp/provider-result.json",
                },
                "selection": {
                    "selected_run_dir": str(self.root / ".auditooor" / "provider_fanout" / "campaign" / "run"),
                    "verification_results": [
                        {
                            "run_dir": str(self.root / ".auditooor" / "provider_fanout" / "campaign" / "old"),
                            "external_run_dir": "/var/tmp/provider-run",
                        }
                    ],
                },
                "remediation_evidence": {
                    "closure_packet_queue": {
                        "path": str(self.root / ".auditooor" / "provider_closure_packet_queue.json")
                    }
                },
            },
        )

        evidence = mod._provider_campaign_evidence(self.root, None)

        self.assertEqual(
            evidence["artifacts"]["local_verification"],
            ".auditooor/provider_fanout/campaign/run/result.json",
        )
        self.assertEqual(evidence["artifacts"]["external"], "/var/tmp/provider-result.json")
        self.assertEqual(
            evidence["selection"]["selected_run_dir"],
            ".auditooor/provider_fanout/campaign/run",
        )
        self.assertEqual(
            evidence["selection"]["verification_results"][0]["run_dir"],
            ".auditooor/provider_fanout/campaign/old",
        )
        self.assertEqual(
            evidence["remediation_evidence"]["closure_packet_queue"]["path"],
            ".auditooor/provider_closure_packet_queue.json",
        )

    def test_lesson_gate_partial_when_source_inventory_has_unpromoted_sources(self) -> None:
        mod = load_module()
        self.seed_common_tools_and_targets()
        write(self.root / "tools" / "agent-artifact-miner.py", "# miner\n")
        write_json(
            self.root / ".auditooor" / "lesson_source_inventory.json",
            {
                "schema": "auditooor.lesson_source_inventory.v1",
                "summary": {
                    "sources_seen": 3,
                    "default_enforcement_sources": 2,
                    "promotion_candidate_sources": 1,
                },
                "coverage_blockers": [
                    {
                        "source_kind": "agent_artifacts",
                        "path": "workspace/.auditooor",
                        "lesson_candidates": 12,
                        "admissibility": "candidate_hard_requires_human_review",
                        "gate_role": "agent_learning_candidate_queue",
                    }
                ],
            },
        )
        write_json(self.root / ".auditooor" / "lesson_enforcement_inventory.json", {"ok": True})

        evidence = mod._lesson_gate_evidence(self.root)

        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(len(evidence["source_coverage_blockers"]), 1)
        self.assertIn("source coverage blockers=1", evidence["reason"])

    def test_cli_json_uses_temp_fixture_repo(self) -> None:
        write(self.root / "Makefile", "field-validation-report:\n\tpython3 tools/field-validation-report.py\n")
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.v3_roadmap_progress_report.v1")
        self.assertEqual(payload["root"], ".")
        self.assertTrue(payload["offline_only"])


if __name__ == "__main__":
    unittest.main()
