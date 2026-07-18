"""Tests for the compact Hackerman MCP tooling index generator."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "hackerman-tooling-index.py"
DOCS_FILE = REPO_ROOT / "docs" / "HACKERMAN_MCP_TOOLING_INDEX.md"
MAKEFILE = REPO_ROOT / "Makefile"


def _load_module():
    spec = importlib.util.spec_from_file_location("hackerman_tooling_index", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()


class HackermanToolingIndexTest(unittest.TestCase):
    def test_manifest_contains_core_workflows(self) -> None:
        index = MODULE.build_index()
        # The manifest is the curated head; Lane-9 exploit-conversion rows are
        # inserted before Wave-1 sections are auto-appended.
        self.assertGreaterEqual(index["workflow_count"], len(MODULE.MANIFEST))
        self.assertEqual(
            index["workflow_count"],
            len(MODULE.MANIFEST)
            + len(MODULE._LANE9_EXPLOIT_CONVERSION_WORKFLOWS)
            + len(MODULE.build_wave1_sections()),
        )

        ids = {row["id"] for row in index["workflows"]}
        for workflow_id in (
            "mcp-session-start",
            "vault-recall-packs",
            "make-audit",
            "make-audit-deep",
            "brain-prime",
            "audit-hacker-logic-bridge",
            "originality-dupe-preproof",
            "control-plane-ready",
            "function-mindset-and-hacker-questions",
            "hackerman-etl-query",
            "hackerman-novel-vector-hypotheses",
            "audit-deep-manifest-summary",
            "predicate-yaml-lint",
            "external-recall-measurement",
            "realworld-recall-gap-priorities",
            "known-limitations-burndown",
            "finalization-manifest",
            "loop-finalization-check",
            "pre-submit-gates",
            "exploit-conversion-loop",
        ):
            self.assertIn(workflow_id, ids)

    def test_markdown_output_mentions_key_commands(self) -> None:
        md = MODULE.render_markdown(MODULE.build_index())
        for needle in (
            "# Hackerman MCP Tooling Index",
            "operator front door, not the full inventory",
            "python3 tools/hackerman-tooling-index.py --format json",
            "python3 tools/hackerman-tooling-index.py --format full-markdown",
            "make session-start",
            "bash tools/auditooor-session-start.sh",
            "vault_resume_context",
            "make audit WS=~/audits/<project>",
            "make audit-deep WS=~/audits/<project>",
            "make exploit-conversion-loop WS=~/audits/<project> TOP_N=10",
            "make brain-prime WS=~/audits/<project>",
            "make brain-prime-dry-run WS=~/audits/<project>",
            "make mined-findings-hunter-bridge WS=~/audits/<project>",
            ".auditooor/mined_findings_hunter_bridge.json",
            ".auditooor/hacker_question_obligations.jsonl",
            "brain_prime_receipt.json",
            "vault_brain_prime_context",
            "Originality / dupe pre-proof recall",
            "Before expensive proof hardening",
            "vault_originality_context",
            "vault_dupe_rejection_context",
            "vault_toolsite_context",
            "Finalization manifest",
            "python3 tools/finalization-manifest.py --workspace ~/audits/<project> --json",
            "python3 tools/vault-mcp-server.py --call vault_finalization_manifest_context --args '{\"workspace_path\":\"~/audits/<project>\"}'",
            "Control-plane-ready Phase A preflight",
            "Dispatch preflight for MCP self-test",
            "make control-plane-ready WS=~/audits/<project> JSON=1",
            "make control-plane-ready WS=~/audits/<project> JSON=1 STRICT=1",
            "python3 tools/control-plane-ready-preflight.py --workspace ~/audits/<project> --json",
            "control plane ready",
            "dispatch preflight",
            "mcp self test",
            "get function mindset",
            "make pre-source-read-inject SOURCE=<path/to/source.go> WORKSPACE=~/audits/<project> TARGET_REPO=owner/repo",
            "make hackerman-refresh DRY_RUN=1",
            "vault_hackerman_chain_candidates",
            "vault_loop_finalization_check",
            "proof_artifact_path",
            "make loop-finalization-check MANIFEST=<path/to/manifest.json>",
            "bash tools/pre-submit-check.sh <draft.md>",
            "python3 tools/high-plus-submission-gate.py <draft.md> --workspace ~/audits/<project> --severity High --json",
            "python3 tools/vault-mcp-server.py --call vault_high_plus_submission_gate",
            "vault_high_plus_submission_gate",
        ):
            self.assertIn(needle, md)
        self.assertLessEqual(len(md.splitlines()), 220)

    def test_checked_in_markdown_matches_generator(self) -> None:
        self.assertEqual(DOCS_FILE.read_text(), MODULE.render_markdown(MODULE.build_index()))

    def test_json_cli_output_is_parseable_and_complete(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["name"], "Hackerman MCP Tooling Index")
        self.assertEqual(data["operator_index"]["schema"], "auditooor.hackerman_operator_index.v1")
        self.assertIn("make capability-roadmap-status JSON=1", data["operator_index"]["gap_probe_commands"])
        self.assertGreaterEqual(data["workflow_count"], 8)
        sections = {row["section"] for row in data["workflows"]}
        self.assertIn("MCP session start", sections)
        self.assertIn("Vault recall packs", sections)
        self.assertIn("Hackerman ETL / query tools", sections)
        self.assertIn("Control-plane-ready Phase A preflight", sections)
        self.assertIn("Function mindset and hacker questions", sections)
        self.assertIn("Hackerman advisory novel-vector hypotheses", sections)
        self.assertIn("Audit-deep manifest summarizer", sections)
        self.assertIn("Known-limitations burndown", sections)
        self.assertIn("Real-world recall gap priorities", sections)
        self.assertIn("Finalization manifest", sections)
        self.assertIn("Loop finalization gate", sections)
        self.assertIn("Pre-submit gates", sections)
        self.assertIn("Predicate YAML lint", sections)

        roadmap = next(row for row in data["workflows"] if row["id"] == "capability-roadmap")
        self.assertIn("vault_toolsite_context", roadmap["callables"])
        self.assertTrue(any("vault_toolsite_context" in cmd for cmd in roadmap["commands"]))

        recall = next(row for row in data["workflows"] if row["id"] == "vault-recall-packs")
        self.assertIn("vault_route", recall["callables"])
        self.assertTrue(any("vault_exploit_context" in cmd for cmd in recall["commands"]))

        brain_prime = next(row for row in data["workflows"] if row["id"] == "brain-prime")
        self.assertIn("brain prime", brain_prime["tasks"])
        self.assertTrue(any("make brain-prime WS=~/audits/<project>" == cmd for cmd in brain_prime["commands"]))
        self.assertIn("vault_brain_prime_context", brain_prime["callables"])
        self.assertIn("brain_prime_receipt.json", brain_prime["summary"])
        self.assertNotIn("`", brain_prime["summary"])

        originality = next(row for row in data["workflows"] if row["id"] == "originality-dupe-preproof")
        self.assertIn("originality before proof", originality["tasks"])
        self.assertIn("originality before proof gate", originality["tasks"])
        self.assertIn("vault_originality_context", originality["callables"])
        self.assertIn("vault_dupe_rejection_context", originality["callables"])
        self.assertTrue(any("originality-before-proof-gate.py" in cmd for cmd in originality["commands"]))
        self.assertTrue(any("dedup-grep.py" in cmd for cmd in originality["commands"]))
        self.assertTrue(any("cross-workspace-duplicate-check.py" in cmd for cmd in originality["commands"]))
        self.assertIn("enforceable pre-proof decision", originality["summary"])

        control_plane_ready = next(row for row in data["workflows"] if row["id"] == "control-plane-ready")
        self.assertIn("control plane ready", control_plane_ready["tasks"])
        self.assertIn("dispatch preflight", control_plane_ready["tasks"])
        self.assertIn("vault_toolsite_context", control_plane_ready["callables"])
        self.assertIn("vault_brain_prime_context", control_plane_ready["callables"])
        self.assertIn("vault_high_impact_execution_bridge_context", control_plane_ready["callables"])
        self.assertTrue(any("control-plane-ready-preflight.py" in cmd for cmd in control_plane_ready["commands"]))
        self.assertIn("not proof or submit readiness", control_plane_ready["summary"])

        hackerman = next(row for row in data["workflows"] if row["id"] == "hackerman-etl-query")
        self.assertTrue(any("hackerman-chain-candidates.py" in cmd for cmd in hackerman["commands"]))
        self.assertTrue(any("hackerman-chain-candidates-sidecar.py" in cmd for cmd in hackerman["commands"]))
        self.assertTrue(any("hackerman-detector-relationships.py" in cmd for cmd in hackerman["commands"]))
        self.assertTrue(any("hackerman-detector-relationships-sidecar.py" in cmd for cmd in hackerman["commands"]))
        self.assertTrue(any("hackerman-go-cosmos-inventory.py" in cmd for cmd in hackerman["commands"]))
        self.assertIn("vault_hackerman_chain_candidates", hackerman["callables"])
        self.assertIn("vault_hackerman_detector_relationships", hackerman["callables"])
        self.assertIn("vault_hackerman_exploit_predicates", hackerman["callables"])
        self.assertIn("vault_hackerman_go_cosmos_inventory", hackerman["callables"])
        self.assertIn("proof_artifact_path", hackerman["summary"])

        novel_vectors = next(row for row in data["workflows"] if row["id"] == "hackerman-novel-vector-hypotheses")
        self.assertIn("novel vector hypotheses", novel_vectors["tasks"])
        self.assertIn("target repo novel vector", novel_vectors["tasks"])
        self.assertTrue(any(cmd == "make hackerman-novel-vector-gen" for cmd in novel_vectors["commands"]))
        self.assertTrue(any("TARGET_REPO=owner/repo JSON=1 MAX_TARGETS=50" in cmd for cmd in novel_vectors["commands"]))
        self.assertTrue(any("audit-deep-novel-vectors" in cmd for cmd in novel_vectors["commands"]))
        self.assertTrue(any("JSONL=1 LIMIT=20" in cmd for cmd in novel_vectors["commands"]))
        self.assertTrue(any("ALL_TARGETS=1" in cmd for cmd in novel_vectors["commands"]))
        self.assertTrue(any("OUT=agent_outputs/novel_vectors.jsonl" in cmd for cmd in novel_vectors["commands"]))
        self.assertTrue(any("hackerman-novel-vector-gen.py" in cmd for cmd in novel_vectors["commands"]))
        self.assertTrue(any("vault_hackerman_novel_vector_context" in cmd for cmd in novel_vectors["commands"]))
        self.assertTrue(any("--max-targets 50" in cmd for cmd in novel_vectors["commands"]))

        deep_manifest = next(row for row in data["workflows"] if row["id"] == "audit-deep-manifest-summary")
        self.assertIn("vault_audit_deep_manifest_summary", deep_manifest["callables"])
        self.assertTrue(any("audit-deep-manifest.py" in cmd for cmd in deep_manifest["commands"]))

        realworld_gap = next(row for row in data["workflows"] if row["id"] == "realworld-recall-gap-priorities")
        self.assertIn("vault_realworld_recall_gap_priorities", realworld_gap["callables"])
        self.assertTrue(any("realworld-recall-gap-prioritizer.py" in cmd for cmd in realworld_gap["commands"]))
        self.assertTrue(any("--all-targets" in cmd for cmd in novel_vectors["commands"]))
        self.assertIn("vault_hackerman_novel_vector_context", novel_vectors["callables"])
        self.assertIn("vault_hackerman_exploit_predicates", novel_vectors["callables"])
        self.assertIn("advisory-only", novel_vectors["summary"])
        self.assertIn("does not claim exploitability, severity, or submission readiness", novel_vectors["summary"])

        finalization_manifest = next(row for row in data["workflows"] if row["id"] == "finalization-manifest")
        self.assertIn("finalization manifest", finalization_manifest["tasks"])
        self.assertIn("inspect current finalization manifest", finalization_manifest["tasks"])
        self.assertTrue(any("finalization-manifest.py" in cmd for cmd in finalization_manifest["commands"]))
        self.assertTrue(any("vault_finalization_manifest_context" in cmd for cmd in finalization_manifest["commands"]))
        self.assertIn("vault_finalization_manifest_context", finalization_manifest["callables"])
        self.assertIn("vault_toolsite_context", finalization_manifest["callables"])
        self.assertNotIn("vault_loop_finalization_check", finalization_manifest["callables"])

        closeout = next(row for row in data["workflows"] if row["id"] == "loop-finalization-check")
        self.assertIn("vault_loop_finalization_check", closeout["callables"])
        self.assertIn("finalize a loop", closeout["tasks"])

        known_limitations = next(row for row in data["workflows"] if row["id"] == "known-limitations-burndown")
        self.assertIn("inspect known limitations", known_limitations["tasks"])
        self.assertTrue(any("known-limitations-burndown" in cmd for cmd in known_limitations["commands"]))

        questions = next(row for row in data["workflows"] if row["id"] == "function-mindset-and-hacker-questions")
        self.assertIn("get function mindset", questions["tasks"])
        self.assertIn("vault_function_mindset", questions["callables"])

    def test_operator_json_cli_output_is_compact_and_live_gap_safe(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--format", "operator-json"],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["schema"], "auditooor.hackerman_operator_index.v1")
        self.assertEqual(data["refresh_command"], "python3 tools/hackerman-tooling-index.py --format operator-json")
        self.assertEqual(data["roadmap_status_command"], "make capability-roadmap-status JSON=1")
        self.assertIn("vault_toolsite_context", data["mcp_discovery_callables"])
        self.assertIn("bash tools/auditooor-session-start.sh ~/audits/<project>", data["first_commands"])
        self.assertIn("make v3-source-first-audit WS=~/audits/<project> TOP_N=25", data["first_commands"])
        self.assertNotIn("make audit WS=~/audits/<project>", data["first_commands"])
        self.assertIn("fresh_session", data["intent_to_workflow_id"])
        self.assertEqual(data["intent_to_workflow_id"]["first_audit_pass"], "v3-source-first-audit")
        self.assertEqual(data["intent_to_workflow_id"]["predicate_yaml_lint"], "predicate-yaml-lint")
        self.assertIn("high_critical_execution_bridge", data["intent_to_workflow_id"])
        self.assertEqual(
            data["intent_to_workflow_id"]["novel_vector_hypotheses"],
            "hackerman-novel-vector-hypotheses",
        )
        self.assertIn("high-impact-execution-bridge", data["workflow_ids_available"])
        self.assertIn("hackerman-novel-vector-hypotheses", data["workflow_ids_available"])
        self.assertIn("current_gap_ids_source", data)
        self.assertNotIn("roadmap_gap_ids", data)

    def test_eight_underused_callables_wired_into_manifest(self) -> None:
        """EXEC-A2 lift: 8 previously-underused MCP callables must appear in some workflow row."""
        index = MODULE.build_index()
        all_callables: set[str] = set()
        for row in index["workflows"]:
            for cb in row.get("callables", []):
                all_callables.add(cb)
        for needed in (
            "vault_function_signature_shape",
            "vault_function_shape_attack_evidence",
            "vault_cross_language_pattern_lift",
            "vault_hackerman_chain_candidates",
            "vault_hackerman_exploit_predicates",
            "vault_hackerman_go_cosmos_inventory",
            "vault_chained_attack_plan_context",
            "vault_toolsite_context",
        ):
            self.assertIn(needed, all_callables, f"missing {needed} from MANIFEST")

    def test_session_start_row_includes_toolsite_context(self) -> None:
        """vault_toolsite_context should be discoverable from the session-start row."""
        index = MODULE.build_index()
        row = next(r for r in index["workflows"] if r["id"] == "mcp-session-start")
        self.assertIn("vault_toolsite_context", row["callables"])

    def test_compact_markdown_source_first_path_is_command_shaped(self) -> None:
        md = MODULE.render_markdown(MODULE.build_index())
        quick_index = md.split("## Operator audit-start quick index", 1)[1].split(
            "## Compact workflow cards", 1
        )[0]
        self.assertNotIn(" then ", quick_index)
        self.assertNotIn(", then ", quick_index)

        v3_card = md.split("## 2. V3 source-first audit", 1)[1].split("## 3.", 1)[0]
        self.assertIn("vault_brain_prime_context", v3_card)
        self.assertIn("vault_exploit_queue_context", v3_card)

    def test_chained_attack_planning_row_present(self) -> None:
        index = MODULE.build_index()
        ids = {row["id"] for row in index["workflows"]}
        self.assertIn("chained-attack-planning", ids)
        row = next(r for r in index["workflows"] if r["id"] == "chained-attack-planning")
        self.assertIn("vault_chained_attack_plan_context", row["callables"])
        self.assertIn("vault_hackerman_exploit_predicates", row["callables"])

    def test_go_cosmos_engagement_bootstrap_row_present(self) -> None:
        index = MODULE.build_index()
        ids = {row["id"] for row in index["workflows"]}
        self.assertIn("go-cosmos-engagement-bootstrap", ids)
        row = next(r for r in index["workflows"] if r["id"] == "go-cosmos-engagement-bootstrap")
        self.assertIn("vault_hackerman_go_cosmos_inventory", row["callables"])
        self.assertIn("vault_cross_language_pattern_lift", row["callables"])

    def test_function_mindset_row_includes_new_signature_and_shape_evidence(self) -> None:
        index = MODULE.build_index()
        row = next(r for r in index["workflows"] if r["id"] == "function-mindset-and-hacker-questions")
        self.assertIn("vault_function_signature_shape", row["callables"])
        self.assertIn("vault_function_shape_attack_evidence", row["callables"])

    def test_wave1_auto_generated_sections_present(self) -> None:
        """Sections 14-17 auto-discover Wave-1 tooling from tools/."""
        index = MODULE.build_index()
        ids = {row["id"] for row in index["workflows"]}
        for wave1_id in (
            "wave1-etl-miners",
            "wave1-stratify-apply-gates",
            "wave1-aggregators",
            "wave1-inspection-preview",
        ):
            self.assertIn(wave1_id, ids, f"missing Wave-1 section: {wave1_id}")

    def test_wave1_etl_miners_section_auto_lists_etl_tools(self) -> None:
        """Section 14 must auto-discover hackerman-etl-from-*.py via glob."""
        index = MODULE.build_index()
        row = next(r for r in index["workflows"] if r["id"] == "wave1-etl-miners")
        # At least the four representative ETL miners we expect on disk.
        for expected in (
            "hackerman-etl-from-contest-platforms.py",
            "hackerman-etl-from-immunefi-public.py",
            "hackerman-etl-from-cve-db.py",
            "hackerman-etl-from-github-advisory.py",
        ):
            self.assertTrue(
                any(expected in cmd for cmd in row["commands"]),
                f"expected ETL miner {expected} in auto-listed commands",
            )
        self.assertGreaterEqual(row["tool_count"], 30)

    def test_wave1_stratify_apply_gates_section_lists_core_gate_tools(self) -> None:
        index = MODULE.build_index()
        row = next(r for r in index["workflows"] if r["id"] == "wave1-stratify-apply-gates")
        for expected in (
            "hackerman-stratify-verification-tier.py",
            "hackerman-apply-verification-tier.py",
            "hackerman-gates-status.py",
            "hackerman-pre-merge.py",
            "hackerman-integrity-check.py",
            "hackerman-tier-history-snapshot.py",
            "hackerman-baseline-freeze.py",
        ):
            self.assertTrue(
                any(expected in cmd for cmd in row["commands"]),
                f"expected gate tool {expected} in auto-listed commands",
            )
        self.assertGreaterEqual(row["tool_count"], 8)

    def test_wave1_aggregators_section_lists_stats_tools(self) -> None:
        index = MODULE.build_index()
        row = next(r for r in index["workflows"] if r["id"] == "wave1-aggregators")
        for expected in (
            "hackerman-corpus-stats.py",
            "hackerman-attack-class-distribution.py",
            "hackerman-attack-class-severity-matrix.py",
            "hackerman-audit-firm-coverage-matrix.py",
            "hackerman-language-stats.py",
            "hackerman-severity-stats.py",
            "hackerman-health-dashboard.py",
            "hackerman-growth-chart.py",
        ):
            self.assertTrue(
                any(expected in cmd for cmd in row["commands"]),
                f"expected aggregator {expected} in auto-listed commands",
            )
        self.assertGreaterEqual(row["tool_count"], 10)

    def test_wave1_inspection_preview_section_lists_record_tools(self) -> None:
        index = MODULE.build_index()
        row = next(r for r in index["workflows"] if r["id"] == "wave1-inspection-preview")
        for expected in (
            "hackerman-record-quality.py",
            "hackerman-record-validate.py",
            "hackerman-record-provenance-audit.py",
            "hackerman-cross-corpus-dupe-finder.py",
            "hackerman-detector-seed-extractor.py",
            "hackerman-audit-firm-pdf-preview-extractor.py",
        ):
            self.assertTrue(
                any(expected in cmd for cmd in row["commands"]),
                f"expected inspection tool {expected} in auto-listed commands",
            )
        self.assertGreaterEqual(row["tool_count"], 10)

    def test_wave1_sections_use_tool_count_in_markdown(self) -> None:
        md = MODULE.render_full_markdown(MODULE.build_index())
        self.assertIn("Auto-discovered tool count:", md)
        self.assertIn("Wave-1 ETL miners", md)
        self.assertIn("Wave-1 stratify / apply / gates", md)
        self.assertIn("Wave-1 aggregators", md)
        self.assertIn("Wave-1 inspection / preview tools", md)

    def test_full_markdown_cli_keeps_exhaustive_inventory_available(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--format", "full-markdown"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("# Hackerman MCP Full Tooling Inventory", proc.stdout)
        self.assertIn("Wave-1 ETL miners", proc.stdout)
        self.assertIn("Auto-discovered tool count:", proc.stdout)

    def test_wave1_discovery_helper_is_robust_to_missing_files(self) -> None:
        """_discover_tools must silently drop allowlist entries that do not
        exist on disk so the generator stays stable across renames."""
        present = MODULE._discover_tools(
            allowlist=["hackerman-corpus-stats.py", "definitely-not-a-real-tool.py"]
        )
        self.assertIn("hackerman-corpus-stats.py", present)
        self.assertNotIn("definitely-not-a-real-tool.py", present)

    def test_pre_submit_row_includes_high_plus_gate(self) -> None:
        index = MODULE.build_index()
        data = json.loads(MODULE.render_json(index))
        pre_submit = next(row for row in data["workflows"] if row["id"] == "pre-submit-gates")
        self.assertIn("vault_high_plus_submission_gate", pre_submit["callables"])
        self.assertIn("high+ submission gate", pre_submit["tasks"])
        self.assertIn("severity axis report", pre_submit["tasks"])
        self.assertTrue(any("high-plus-submission-gate.py" in cmd for cmd in pre_submit["commands"]))
        self.assertTrue(any("severity-calibration-gate.py" in cmd for cmd in pre_submit["commands"]))

    def test_external_recall_row_includes_manifest_and_scoreboard(self) -> None:
        index = MODULE.build_index()
        data = json.loads(MODULE.render_json(index))
        row = next(item for item in data["workflows"] if item["id"] == "external-recall-measurement")
        self.assertIn("external repo recall", row["tasks"])
        self.assertTrue(any("external-recall-manifest.py select" in cmd for cmd in row["commands"]))
        self.assertTrue(any("external-recall-manifest.py build" in cmd for cmd in row["commands"]))
        self.assertTrue(any("realworld-recall-scoreboard.py" in cmd for cmd in row["commands"]))

    def test_predicate_yaml_lint_row_is_advisory_by_default(self) -> None:
        index = MODULE.build_index()
        data = json.loads(MODULE.render_json(index))
        row = next(item for item in data["workflows"] if item["id"] == "predicate-yaml-lint")
        self.assertIn("predicate yaml lint", row["tasks"])
        self.assertIn("vault_toolsite_context", row["callables"])
        self.assertTrue(any(cmd == "make predicate-yaml-lint" for cmd in row["commands"]))
        self.assertTrue(any("STRICT=1" in cmd for cmd in row["commands"]))
        self.assertIn("strict mode is opt-in", row["summary"])

    def test_go_cosmos_row_includes_production_harness_plan(self) -> None:
        index = MODULE.build_index()
        data = json.loads(MODULE.render_json(index))
        row = next(item for item in data["workflows"] if item["id"] == "go-cosmos-engagement-bootstrap")
        self.assertTrue(any("cosmos-production-harness-plan.py" in cmd for cmd in row["commands"]))
        self.assertTrue(any("cosmos-production-harness-tasks.py" in cmd for cmd in row["commands"]))
        self.assertTrue(any("make cosmos-production-harness-plan" in cmd for cmd in row["commands"]))
        self.assertTrue(any("make cosmos-production-harness-tasks" in cmd for cmd in row["commands"]))

    def test_novel_vector_make_target_is_discoverable(self) -> None:
        makefile = MAKEFILE.read_text()
        self.assertIn(".PHONY: hackerman-chain-candidates-sidecar", makefile)
        self.assertIn("hackerman-novel-vector-gen", makefile)
        self.assertIn("audit-deep-novel-vectors", makefile)
        self.assertIn("tools/hackerman-novel-vector-gen.py", makefile)
        self.assertIn("tools/audit-deep-novel-vectors.py", makefile)
        self.assertIn('$(if $(JSON),--json)', makefile)
        self.assertIn('$(if $(JSONL),--out "$(if $(OUT),$(OUT),-)"', makefile)
        self.assertIn('$(if $(OUT),--out "$(OUT)")', makefile)
        self.assertIn('$(if $(TARGET_REPO),--target-repo "$(TARGET_REPO)")', makefile)
        self.assertIn('$(if $(MAX_TARGETS),--max-targets "$(MAX_TARGETS)")', makefile)
        self.assertIn('$(if $(ALL_TARGETS),--all-targets)', makefile)
        self.assertIn('$(if $(SAME_CLASS_VARIANTS),--same-class-variants)', makefile)

    def test_pre_source_read_make_target_points_at_wave6_injector(self) -> None:
        makefile = MAKEFILE.read_text()
        self.assertIn("tools/auditooor-pre-source-read-injector.py", makefile)
        self.assertIn("pre-source-read-inject-legacy", makefile)
        self.assertIn("tools/pre-source-read-inject.py", makefile)
        self.assertIn('$(if $(TARGET_REPO),--target-repo "$(TARGET_REPO)")', makefile)
        self.assertIn('$(if $(TOP_N),--top-n "$(TOP_N)")', makefile)
        self.assertIn('$(if $(MIN_CONFIDENCE),--min-confidence "$(MIN_CONFIDENCE)")', makefile)
        self.assertIn('$(if $(MAX_FUNCTIONS),--max-functions "$(MAX_FUNCTIONS)")', makefile)
        self.assertIn("tools.tests.test_pre_source_read_injector", makefile)


if __name__ == "__main__":
    unittest.main()
