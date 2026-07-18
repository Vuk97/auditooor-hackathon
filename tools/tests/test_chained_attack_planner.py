from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "chained-attack-planner.py"
DRIVER = ROOT / "tools" / "chain-synth-driver.py"
PRECHECK = ROOT / "tools" / "escalation-chain-precheck.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("chained_attack_planner", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load chained-attack-planner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_driver():
    spec = importlib.util.spec_from_file_location("chain_synth_driver", DRIVER)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load chain-synth-driver.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _exploit_angle(
    angle_id: str,
    title: str,
    *,
    target_files: list[str],
    proof_prerequisites: list[dict],
    source_refs: list[str] | None = None,
) -> dict:
    return {
        "angle_id": angle_id,
        "title": title,
        "recommendation_status": "recommended",
        "protocol_family": "vault",
        "bug_class_id": angle_id,
        "target_files": target_files,
        "source_refs": source_refs or [f"workspace:{target_files[0]}:10"],
        "live_prerequisites": [],
        "hypothesis": f"Check whether {title.lower()} composes with another state transition.",
        "attack_surface": ", ".join(target_files),
        "ranking_rationale": "score=4 source_signal=2 source_matches=1 accepted=0 duplicates=0",
        "prior_outcome_signal": {
            "accepted_count": 0,
            "duplicate_count": 0,
            "rejected_count": 0,
            "sample_size": 0,
        },
        "nearest_prior_workspaces": [],
        "duplicate_guard": {
            "status": "clear",
            "material_distinction": "",
            "evidence_chain": ["repo:reference/outcomes.jsonl"],
        },
        "oos_guard": {
            "status": "scope_artifact_present_manual_review",
            "clause_refs": ["workspace:SCOPE.md"],
            "rationale": "Scope artifact present; per-finding OOS gate still required.",
        },
        "proof_prerequisites": proof_prerequisites,
        "required_artifacts_for_high_critical": [],
        "harness_failure_refs": [],
        "knowledge_gap_refs": [],
        "detector_saturation": 1,
        "source_signal_score": 2.0,
        "evidence_chain": list(source_refs or []),
        "confidence": "medium",
        "sample_size": 0,
        "last_validated_at": "2026-05-12",
        "counter_examples": [],
        "recommended_next_command": "collect source proof",
        "not_submit_ready_until": ["pre-submit gate passes", "proof artifacts execute"],
        "outcome_semantics": {
            "unknown_reason_declines_learning_scope": "platform_base_rate_only",
            "cause_learning_allowed": False,
        },
    }


class ChainedAttackPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        (self.ws / ".auditooor").mkdir()
        (self.ws / "swarm").mkdir()
        (self.ws / "src").mkdir()
        (self.ws / "src" / "Vault.sol").write_text(
            "\n".join(f"// vault line {i}" for i in range(1, 61)) + "\n",
            encoding="utf-8",
        )
        (self.ws / "src" / "Router.sol").write_text(
            "\n".join(f"// router line {i}" for i in range(1, 61)) + "\n",
            encoding="utf-8",
        )
        (self.ws / "SEVERITY.md").write_text(
            "# Severity Rubric\n\n"
            "- Direct loss of funds.\n"
            "- Unintended permanent chain split requiring hard fork.\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_chain_synth_mirror_never_clobbers_canonical_v1_report(self) -> None:
        """The planner mirrors to chain_synthesis_<date>.json for the gate, but
        chain-synth-driver.py owns that path with the authoritative
        auditooor.chain_synthesis_report.v1 schema. The mirror must NOT overwrite
        a v1 report (the hyperlane chain-synth false-fail: a plans-schema mirror
        silently clobbered the driver's input_counts-bearing report)."""
        tool = _load_tool()
        mirror = self.ws / ".auditooor" / "chain_synthesis_2026-06-21.json"
        plans_payload = {"schema": "auditooor.chained_attack_plans.v1", "plans": []}

        # 1) absent -> mirror is written (path-gap close when planner is the step)
        self.assertTrue(tool._write_chain_synth_mirror(mirror, plans_payload))
        self.assertEqual(
            json.loads(mirror.read_text())["schema"],
            "auditooor.chained_attack_plans.v1")

        # 2) a plans-schema mirror may be refreshed (legacy behavior preserved)
        self.assertTrue(tool._write_chain_synth_mirror(mirror, plans_payload))

        # 3) a canonical v1 report present -> mirror is SKIPPED, report preserved
        mirror.write_text(json.dumps({
            "schema": "auditooor.chain_synthesis_report.v1",
            "status": "no-invariant-ids",
            "input_counts": {"current_queue_leads": 502},
        }), encoding="utf-8")
        self.assertFalse(tool._write_chain_synth_mirror(mirror, plans_payload))
        preserved = json.loads(mirror.read_text())
        self.assertEqual(preserved["schema"], "auditooor.chain_synthesis_report.v1")
        self.assertEqual(preserved["input_counts"]["current_queue_leads"], 502)

    def test_shared_target_file_and_proof_prereq_emit_candidate_chain(self) -> None:
        tool = _load_tool()
        exploit = {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace_path": str(self.ws),
            "angles": [
                _exploit_angle(
                    "angle-001",
                    "withdraw accounting drift",
                    target_files=["src/Vault.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
                _exploit_angle(
                    "angle-002",
                    "cap desync",
                    target_files=["src/Vault.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
            ],
        }
        _write_json(self.ws / ".auditooor" / "exploit_memory_brief.json", exploit)

        payload = tool.run(["--workspace", str(self.ws)])

        self.assertEqual(payload["summary"]["plan_count"], 1)
        self.assertEqual(payload["workspace"], "<workspace>")
        self.assertNotIn(str(self.ws), json.dumps(payload))
        plan = payload["plans"][0]
        self.assertEqual(plan["chain_id"], "CHAIN-001")
        self.assertEqual(plan["status"], "candidate_not_submit_ready")
        self.assertIn("collect proof pair", plan["proof_steps"])
        self.assertIn("pre-submit gate has not passed", plan["blockers"])
        self.assertTrue(
            any(item.startswith("shared_files:src/Vault.sol") for item in plan["shared_evidence"])
        )

    def test_previous_chain_rows_are_not_recomposed_as_new_primitives(self) -> None:
        tool = _load_tool()
        candidates = [
            {
                "candidate_id": "EQ-DIRECT",
                "title": "direct source candidate",
                "target_files": ["src/Vault.sol"],
                "source_refs": ["workspace:src/Vault.sol:10"],
            },
            {
                "candidate_id": "EQ-CHAIN",
                "chain_id": "CHAIN-OLD",
                "title": "Chain CHAIN-OLD: prior composition",
                "target_files": ["src/Vault.sol"],
                "source_refs": ["workspace:src/Vault.sol:10"],
            },
            {
                "candidate_id": "EQ-CLOSED",
                "title": "Closed negative candidate",
                "proof_status": "closed_negative",
                "target_files": ["src/Vault.sol"],
                "source_refs": ["workspace:src/Vault.sol:10"],
            },
        ]

        payload = tool._build_payload(
            self.ws,
            None,
            None,
            {"candidates": candidates},
            self.ws / "swarm" / "brief_candidates.json",
            None,
            None,
            None,
            "auto",
            [],
            [],
            [],
            [],
            10,
        )

        self.assertEqual(payload["summary"]["brief_candidate_count"], 1)
        self.assertEqual(payload["summary"]["chain_candidate_excluded_count"], 1)
        self.assertEqual(payload["summary"]["terminal_candidate_excluded_count"], 1)

    def test_detector_cluster_on_angle_file_becomes_advisory_chain_step(self) -> None:
        tool = _load_tool()
        exploit = {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace_path": str(self.ws),
            "angles": [
                _exploit_angle(
                    "angle-001",
                    "withdraw accounting drift",
                    target_files=["src/Vault.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
            ],
        }
        engage_report = (
            "# Engagement Report\n\n"
            "- Total hits: **1**\n"
            "- Distinct detectors: **1**\n"
            "- Analogical clusters: **1**\n\n"
            "## Clusters\n\n"
            "### Cluster: `reentrancy-no-guard` (1 hits)\n\n"
            f"- **[HIGH] `reentrancy-no-guard`** - `{self.ws}/src/Vault.sol:42`\n"
            "  - snippet: `function withdraw(uint256 amount) external {`\n"
        )
        _write_json(self.ws / ".auditooor" / "exploit_memory_brief.json", exploit)
        (self.ws / "engage_report.md").write_text(engage_report, encoding="utf-8")

        payload = tool.run(["--workspace", str(self.ws)])

        self.assertEqual(payload["summary"]["detector_cluster_count"], 1)
        plan = payload["plans"][0]
        self.assertEqual(plan["status"], "candidate_not_submit_ready")
        self.assertTrue(any(item["source_kind"] == "detector_cluster" for item in plan["primitives"]))
        detector_steps = [row for row in plan["chain_steps"] if row["source_kind"] == "detector_cluster"]
        self.assertEqual(len(detector_steps), 1)
        self.assertTrue(detector_steps[0]["advisory_only"])
        self.assertEqual(detector_steps[0]["detector_slug"], "reentrancy-no-guard")
        self.assertIn("shared_files:src/Vault.sol", plan["shared_evidence"])
        self.assertIn(
            "detector cluster is source signal only until file:line proof is manually confirmed",
            plan["blockers"],
        )

    def test_engage_report_json_sidecar_preferred_over_markdown(self) -> None:
        tool = _load_tool()
        exploit = {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace_path": str(self.ws),
            "angles": [
                _exploit_angle(
                    "angle-001",
                    "sidecar preference check",
                    target_files=["src/Sidecar.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
            ],
        }
        engage_report_md = (
            "# Engagement Report\n\n"
            "- Total hits: **1**\n"
            "- Distinct detectors: **1**\n"
            "- Analogical clusters: **1**\n\n"
            "## Clusters\n\n"
            "### Cluster: `markdown-cluster` (1 hits)\n\n"
            f"- **[HIGH] `markdown-cluster`** - `{self.ws}/src/Markdown.sol:11`\n"
            "  - snippet: `markdown-only signal`\n"
        )
        engage_report_json = {
            "schema": "auditooor.engage_report.sidecar.v1",
            "kind": "engage_report_sidecar",
            "clusters": [
                {
                    "detector_slug": "json-sidecar-cluster",
                    "hit_count": 1,
                    "hits": [
                        {
                            "severity": "HIGH",
                            "file_path": f"{self.ws}/src/Sidecar.sol:33",
                            "snippet": "json sidecar signal",
                        }
                    ],
                }
            ],
        }
        _write_json(self.ws / ".auditooor" / "exploit_memory_brief.json", exploit)
        (self.ws / "engage_report.md").write_text(engage_report_md, encoding="utf-8")
        _write_json(self.ws / "engage_report.json", engage_report_json)

        payload = tool.run(["--workspace", str(self.ws)])

        self.assertEqual(payload["summary"]["detector_cluster_count"], 1)
        plan = payload["plans"][0]
        detector_steps = [row for row in plan["chain_steps"] if row["source_kind"] == "detector_cluster"]
        self.assertEqual(len(detector_steps), 1)
        self.assertEqual(detector_steps[0]["detector_slug"], "json-sidecar-cluster")
        self.assertIn("shared_files:src/Sidecar.sol", plan["shared_evidence"])

    def test_invalid_engage_report_json_sidecar_falls_back_to_markdown(self) -> None:
        tool = _load_tool()
        exploit = {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace_path": str(self.ws),
            "angles": [
                _exploit_angle(
                    "angle-001",
                    "markdown fallback check",
                    target_files=["src/Vault.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
            ],
        }
        engage_report_md = (
            "# Engagement Report\n\n"
            "- Total hits: **1**\n"
            "- Distinct detectors: **1**\n"
            "- Analogical clusters: **1**\n\n"
            "## Clusters\n\n"
            "### Cluster: `markdown-fallback-cluster` (1 hits)\n\n"
            f"- **[HIGH] `markdown-fallback-cluster`** - `{self.ws}/src/Vault.sol:42`\n"
            "  - snippet: `fallback detector hit`\n"
        )
        _write_json(self.ws / ".auditooor" / "exploit_memory_brief.json", exploit)
        (self.ws / "engage_report.md").write_text(engage_report_md, encoding="utf-8")
        (self.ws / "engage_report.json").write_text("{not-json", encoding="utf-8")

        payload = tool.run(["--workspace", str(self.ws)])

        self.assertEqual(payload["summary"]["detector_cluster_count"], 1)
        plan = payload["plans"][0]
        detector_steps = [row for row in plan["chain_steps"] if row["source_kind"] == "detector_cluster"]
        self.assertEqual(len(detector_steps), 1)
        self.assertEqual(detector_steps[0]["detector_slug"], "markdown-fallback-cluster")
        self.assertIn("shared_files:src/Vault.sol", plan["shared_evidence"])

    def test_defihack_predicate_match_chains_with_detector_attack_class_overlap(self) -> None:
        tool = _load_tool()
        engage_report = (
            "# Engagement Report\n\n"
            "- Total hits: **1**\n"
            "- Distinct detectors: **1**\n"
            "- Analogical clusters: **1**\n\n"
            "## Clusters\n\n"
            "### Cluster: `spot-lp-oracle-manipulation` (1 hits)\n\n"
            f"- **[HIGH] `spot-lp-oracle-manipulation`** - `{self.ws}/src/OracleConsumer.sol:42`\n"
            "  - snippet: `uint price = oracle.getPrice();`\n"
        )
        defihack_report = (
            "# DeFiHackLabs class-matcher report\n\n"
            "## Per-row results\n\n"
            "### dhl-005 - spot-lp-oracle-manipulation [CANDIDATE-SEED]\n\n"
            "**Mechanism**: Protocol reads instantaneous AMM spot price as collateral oracle.  \n"
            "**Detector status**: gap  \n"
            "**Pattern** `getReserves\\(\\)` -> 1 hit(s):\n"
            "```\n"
            f"{self.ws}/src/PriceOracle.sol:7: IUniswapV2Pair(pair).getReserves();\n"
            "```\n"
        )
        (self.ws / "engage_report.md").write_text(engage_report, encoding="utf-8")
        report_path = self.ws / "scan-results" / "defihack-match-test" / "match_report.md"
        report_path.parent.mkdir(parents=True)
        report_path.write_text(defihack_report, encoding="utf-8")

        payload = tool.run([
            "--workspace", str(self.ws),
            "--defihack-report", str(report_path),
        ])

        self.assertEqual(payload["summary"]["detector_cluster_count"], 1)
        self.assertEqual(payload["summary"]["defihack_predicate_match_count"], 1)
        self.assertEqual(payload["summary"]["plan_count"], 1)
        plan = payload["plans"][0]
        kinds = {item["source_kind"] for item in plan["primitives"]}
        self.assertIn("detector_cluster", kinds)
        self.assertIn("defihack_predicate_match", kinds)
        self.assertIn("shared_attack_classes:spot-lp-oracle-manipulation", plan["shared_evidence"])
        self.assertIn(
            "DeFiHack predicate match is corpus analogue only until file:line exploitability is confirmed",
            plan["blockers"],
        )
        self.assertTrue(
            any(row["source_kind"] == "defihack_predicate_match" and row["advisory_only"] for row in plan["chain_steps"])
        )

    def test_defihack_predicate_match_without_material_overlap_does_not_chain(self) -> None:
        tool = _load_tool()
        engage_report = (
            "# Engagement Report\n\n"
            "- Total hits: **1**\n"
            "- Distinct detectors: **1**\n"
            "- Analogical clusters: **1**\n\n"
            "## Clusters\n\n"
            "### Cluster: `vault-accounting-drift` (1 hits)\n\n"
            f"- **[HIGH] `vault-accounting-drift`** - `{self.ws}/src/Vault.sol:42`\n"
            "  - snippet: `totalAssets -= amount;`\n"
        )
        defihack_report = (
            "# DeFiHackLabs class-matcher report\n\n"
            "## Per-row results\n\n"
            "### dhl-005 - spot-lp-oracle-manipulation [CANDIDATE-SEED]\n\n"
            "**Mechanism**: Protocol reads instantaneous AMM spot price as collateral oracle.  \n"
            "**Detector status**: gap  \n"
            "**Pattern** `getReserves\\(\\)` -> 1 hit(s):\n"
            "```\n"
            f"{self.ws}/src/PriceOracle.sol:7: IUniswapV2Pair(pair).getReserves();\n"
            "```\n"
        )
        (self.ws / "engage_report.md").write_text(engage_report, encoding="utf-8")
        report_path = self.ws / "scan-results" / "defihack-match-test" / "match_report.md"
        report_path.parent.mkdir(parents=True)
        report_path.write_text(defihack_report, encoding="utf-8")

        payload = tool.run([
            "--workspace", str(self.ws),
            "--defihack-report", str(report_path),
        ])

        self.assertEqual(payload["summary"]["defihack_predicate_match_count"], 1)
        self.assertEqual(payload["summary"]["plan_count"], 0)

    def test_hacker_brief_qdet_same_observation_does_not_chain_without_bridge_signal(self) -> None:
        tool = _load_tool()
        engage_report = (
            "# Engagement Report\n\n"
            "- Total hits: **1**\n"
            "- Distinct detectors: **1**\n"
            "- Analogical clusters: **1**\n\n"
            "## Clusters\n\n"
            "### Cluster: `cap-desync` (1 hits)\n\n"
            f"- **[HIGH] `cap-desync`** - `{self.ws}/src/Vault.sol:55`\n"
            "  - snippet: `cap = cap - amount;`\n"
        )
        sidecar = {
            "schema": "auditooor.hacker_brief_augmenter.v1",
            "lane_id": "H1-vault",
            "workspace": "<workspace>",
            "files": ["src/Vault.sol"],
            "sections": {
                "sec5_engage_report_fires": {
                    "items": [
                        {
                            "detector": "cap-desync",
                            "fires": ["[HIGH] src/Vault.sol:55 - cap = cap - amount;"],
                            "count": 1,
                        }
                    ]
                },
                "sec13_question_list": {
                    "items": [
                        {
                            "id": "Q-DET-cap-desync",
                            "text": "Was detector fire `cap-desync` investigated end-to-end?",
                            "evidence": "File:line confirmed or ruled out",
                        }
                    ]
                },
            },
        }
        (self.ws / "engage_report.md").write_text(engage_report, encoding="utf-8")
        _write_json(self.ws / ".auditooor" / "hacker_brief.md.json", sidecar)

        payload = tool.run(["--workspace", str(self.ws)])

        self.assertEqual(payload["summary"]["detector_cluster_count"], 1)
        self.assertEqual(payload["summary"]["hacker_brief_qdet_count"], 1)
        self.assertEqual(payload["summary"]["plan_count"], 0)

    def test_hacker_brief_qdet_chains_when_distinct_bridge_signal_matches(self) -> None:
        tool = _load_tool()
        engage_report = (
            "# Engagement Report\n\n"
            "- Total hits: **1**\n"
            "- Distinct detectors: **1**\n"
            "- Analogical clusters: **1**\n\n"
            "## Clusters\n\n"
            "### Cluster: `cap-desync` (1 hits)\n\n"
            f"- **[HIGH] `cap-desync`** - `{self.ws}/src/Vault.sol:55`\n"
            "  - snippet: `cap = cap - amount; bridge_signal:LIVE-PAIR-01`\n"
        )
        sidecar = {
            "schema": "auditooor.hacker_brief_augmenter.v1",
            "lane_id": "H1-vault",
            "workspace": "<workspace>",
            "files": ["src/Vault.sol"],
            "sections": {
                "sec5_engage_report_fires": {
                    "items": [
                        {
                            "detector": "cap-desync",
                            "fires": ["[HIGH] src/Vault.sol:55 - cap = cap - amount;"],
                            "count": 1,
                        }
                    ]
                },
                "sec13_question_list": {
                    "items": [
                        {
                            "id": "Q-DET-cap-desync",
                            "text": "Was detector fire `cap-desync` investigated end-to-end?",
                            "evidence": "File:line confirmed or ruled out with bridge_signal:LIVE-PAIR-01",
                            "causal_bridge_signals": ["LIVE-PAIR-01"],
                        }
                    ]
                },
            },
        }
        (self.ws / "engage_report.md").write_text(engage_report, encoding="utf-8")
        _write_json(self.ws / ".auditooor" / "hacker_brief.md.json", sidecar)

        payload = tool.run(["--workspace", str(self.ws)])

        self.assertEqual(payload["summary"]["detector_cluster_count"], 1)
        self.assertEqual(payload["summary"]["hacker_brief_qdet_count"], 1)
        self.assertEqual(payload["summary"]["plan_count"], 1)
        plan = payload["plans"][0]
        self.assertGreater(plan["score"], 1)
        self.assertEqual(plan["status"], "candidate_not_submit_ready")
        kinds = {item["source_kind"] for item in plan["primitives"]}
        self.assertIn("detector_cluster", kinds)
        self.assertIn("hacker_brief_qdet", kinds)
        self.assertIn("shared_detectors:cap-desync", plan["shared_evidence"])
        self.assertIn("shared_causal_bridge_signals:live-pair-01", plan["shared_evidence"])
        self.assertTrue(
            any(row["source_kind"] == "hacker_brief_qdet" for row in plan["chain_steps"])
        )
        self.assertIn("hacker-brief detector question Q-DET-cap-desync is unanswered", plan["blockers"])

    def test_default_hacker_brief_loader_ignores_stale_lane_sidecars(self) -> None:
        """Only the canonical hacker_brief.md.json is auto-loaded by default."""
        tool = _load_tool()
        stale_sidecar = {
            "schema": "auditooor.hacker_brief_augmenter.v1",
            "lane_id": "stale",
            "files": ["src/Stale.sol"],
            "sections": {
                "sec13_question_list": {
                    "items": [
                        {
                            "id": "Q-DET-stale-detector",
                            "text": "Was stale detector investigated?",
                            "evidence": "stale evidence",
                        }
                    ]
                }
            },
        }
        canonical_sidecar = {
            "schema": "auditooor.hacker_brief_augmenter.v1",
            "lane_id": "current",
            "files": ["src/Vault.sol"],
            "sections": {
                "sec13_question_list": {
                    "items": [
                        {
                            "id": "Q-DET-current-detector",
                            "text": "Was current detector investigated?",
                            "evidence": "current evidence",
                        }
                    ]
                }
            },
        }
        _write_json(self.ws / ".auditooor" / "hacker_brief_stale.md.json", stale_sidecar)
        _write_json(self.ws / ".auditooor" / "hacker_brief.md.json", canonical_sidecar)

        rows = tool._load_hacker_brief_primitives(self.ws, [])

        self.assertEqual(len(rows), 1)
        self.assertIn("current-detector", json.dumps(rows))
        self.assertNotIn("stale-detector", json.dumps(rows))

    def test_paired_live_rows_emit_but_source_ref_only_overlap_is_ignored(self) -> None:
        tool = _load_tool()
        brief_candidates = {
            "candidates": [
                {
                    "source_file": str(self.ws / "swarm" / "brief_a.md"),
                    "kind": "poc_plan",
                    "contract": "Vault",
                    "angle_id": "A-LIVE-1",
                    "angle_title": "live chain one",
                    "matched_mining_briefs": [],
                    "proof_poor": False,
                    "paired_live_row_ids": ["LIVE-PAIR-01"],
                    "paired_contracts": ["BridgeEscrow"],
                    "involved_contracts": ["Vault", "BridgeEscrow"],
                    "executed_live_rows": False,
                    "suggested_functions": [],
                    "exploit_goal": "turn queue delay into cross-contract withdrawal freeze",
                    "recommended_next_step": "execute paired live rows",
                },
                {
                    "source_file": str(self.ws / "swarm" / "brief_b.md"),
                    "kind": "poc_plan",
                    "contract": "Vault",
                    "angle_id": "A-LIVE-2",
                    "angle_title": "live chain two",
                    "matched_mining_briefs": [],
                    "proof_poor": False,
                    "paired_live_row_ids": ["LIVE-PAIR-01"],
                    "paired_contracts": ["BridgeEscrow"],
                    "involved_contracts": ["Vault", "BridgeEscrow"],
                    "executed_live_rows": False,
                    "suggested_functions": [],
                    "exploit_goal": "replay the same row pairing into a broader freeze",
                    "recommended_next_step": "execute paired live rows",
                },
                {
                    "source_file": str(self.ws / "swarm" / "shared.md"),
                    "kind": "candidate_finding",
                    "contract": "Router",
                    "angle_id": "A-SRC-1",
                    "angle_title": "source overlap one",
                    "matched_mining_briefs": [],
                    "proof_poor": False,
                    "paired_live_row_ids": [],
                    "paired_contracts": [],
                    "involved_contracts": ["Router"],
                    "executed_live_rows": False,
                    "suggested_functions": [],
                    "exploit_goal": "source-only overlap one",
                    "recommended_next_step": "collect source proof",
                },
                {
                    "source_file": str(self.ws / "swarm" / "shared.md"),
                    "kind": "candidate_finding",
                    "contract": "Oracle",
                    "angle_id": "A-SRC-2",
                    "angle_title": "source overlap two",
                    "matched_mining_briefs": [],
                    "proof_poor": False,
                    "paired_live_row_ids": [],
                    "paired_contracts": [],
                    "involved_contracts": ["Oracle"],
                    "executed_live_rows": False,
                    "suggested_functions": [],
                    "exploit_goal": "source-only overlap two",
                    "recommended_next_step": "collect source proof",
                },
            ]
        }
        _write_json(self.ws / "swarm" / "brief_candidates.json", brief_candidates)

        payload = tool.run(["--workspace", str(self.ws)])

        self.assertEqual(payload["summary"]["plan_count"], 1)
        top = payload["plans"][0]
        top_ids = {item["primitive_id"] for item in top["primitives"]}
        self.assertTrue(any("A-LIVE-1" in item or "A-LIVE-2" in item for item in top_ids))
        self.assertFalse(any("A-SRC-1" in item or "A-SRC-2" in item for item in top_ids))

    def test_brief_candidate_source_links_skip_without_queue_lead_ids(self) -> None:
        tool = _load_tool()
        driver = _load_driver()
        brief_candidates = {
            "candidates": [
                {
                    "source_file": str(self.ws / "swarm" / "brief_a.md"),
                    "kind": "poc_plan",
                    "contract": "Vault",
                    "angle_id": "A-LIVE-A",
                    "angle_title": "live source link A",
                    "matched_mining_briefs": [],
                    "broken_invariant_ids": ["INV-LIVE-A"],
                    "paired_live_row_ids": ["LIVE-PAIR-01"],
                    "paired_contracts": ["BridgeEscrow"],
                    "involved_contracts": ["Vault", "BridgeEscrow"],
                    "executed_live_rows": False,
                    "source_refs": ["workspace:src/Vault.sol:10"],
                    "suggested_functions": [],
                    "exploit_goal": "turn live pair into source-backed producer state",
                    "recommended_next_step": "execute paired live rows",
                },
                {
                    "source_file": str(self.ws / "swarm" / "brief_b.md"),
                    "kind": "poc_plan",
                    "contract": "BridgeEscrow",
                    "angle_id": "A-LIVE-B",
                    "angle_title": "live source link B",
                    "matched_mining_briefs": [],
                    "broken_invariant_ids": ["INV-LIVE-B"],
                    "paired_live_row_ids": ["LIVE-PAIR-01"],
                    "paired_contracts": ["BridgeEscrow"],
                    "involved_contracts": ["Vault", "BridgeEscrow"],
                    "executed_live_rows": False,
                    "source_refs": ["workspace:src/Escrow.sol:20"],
                    "suggested_functions": [],
                    "exploit_goal": "consume live pair in the escrow transition",
                    "recommended_next_step": "execute paired live rows",
                },
            ]
        }
        _write_json(self.ws / "swarm" / "brief_candidates.json", brief_candidates)

        payload = tool.run(["--workspace", str(self.ws), "--emit-chain-synth-source-links"])

        self.assertEqual(payload["summary"]["plan_count"], 1)
        plan = payload["plans"][0]
        self.assertEqual(plan["causal_evidence_level"], "distinct_bridge_signal_present")
        self.assertEqual(plan["broken_invariant_ids"], ["INV-LIVE-A", "INV-LIVE-B"])
        self.assertIn("workspace:src/Vault.sol:10", plan["source_refs"])
        self.assertIn("workspace:src/Escrow.sol:20", plan["source_refs"])
        source_link_doc = json.loads(
            (self.ws / ".auditooor" / "chain_synth_source_links.json").read_text(encoding="utf-8")
        )
        self.assertEqual(source_link_doc["links"], [])
        entries = driver.load_source_link_entries(self.ws)
        self.assertEqual(entries, [])

    def test_big_loss_actor_sequence_imported_as_advisory_chain_steps(self) -> None:
        tool = _load_tool()
        exploit = {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace_path": str(self.ws),
            "angles": [
                _exploit_angle(
                    "angle-001",
                    "proof domain mismatch",
                    target_files=["AggregateVerifier.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect verifier proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
                _exploit_angle(
                    "angle-002",
                    "bridge withdrawal misroute",
                    target_files=["AggregateVerifier.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect verifier proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
            ],
        }
        ledger = {
            "schema_version": "auditooor.invariant_ledger.v1",
            "workspace": str(self.ws),
            "rows": [
                {
                    "id": "BASE-SC-I01",
                    "invariant_family": "BASE-SC-PROOF-DOMAIN",
                    "production_path": "AggregateVerifier.verify(proofType, proofData) -> AggregateVerifier.sol",
                    "severity": "Critical",
                    "status": "executed_clean",
                }
            ],
        }
        _write_json(self.ws / ".auditooor" / "exploit_memory_brief.json", exploit)
        _write_json(self.ws / ".auditooor" / "invariant_ledger.json", ledger)

        payload = tool.run(["--workspace", str(self.ws)])

        plan = payload["plans"][0]
        self.assertTrue(any(item["source_kind"] == "big_loss_actor_sequence" for item in plan["primitives"]))
        actor_steps = [row for row in plan["chain_steps"] if row["source_kind"] == "big_loss_actor_sequence"]
        self.assertTrue(actor_steps)
        self.assertTrue(all(row["advisory_only"] for row in actor_steps))
        self.assertNotIn("ledger:BASE-SC-I01", plan["proof_steps"])

    def test_lone_big_loss_without_file_or_contract_overlap_is_not_attached(self) -> None:
        tool = _load_tool()
        exploit = {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace_path": str(self.ws),
            "angles": [
                _exploit_angle(
                    "angle-001",
                    "vault accounting drift",
                    target_files=["src/Vault.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
                _exploit_angle(
                    "angle-002",
                    "vault cap desync",
                    target_files=["src/Vault.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
            ],
        }
        big_loss = {
            "manifests": [
                {
                    "composed_status": "composed",
                    "row_id": "BRIDGE-ROW",
                    "template_id": "bridge_proof_domain",
                    "actor_sequence": [
                        {
                            "actor": "attacker",
                            "action": "submit proof",
                            "target": "BridgeVerifier.verify",
                            "evidence_required": "proof accepted",
                        }
                    ],
                }
            ]
        }
        _write_json(self.ws / ".auditooor" / "exploit_memory_brief.json", exploit)
        _write_json(self.ws / ".auditooor" / "big_loss_template_composed.json", big_loss)

        payload = tool.run(["--workspace", str(self.ws)])

        plan = payload["plans"][0]
        self.assertFalse(any(item["source_kind"] == "big_loss_actor_sequence" for item in plan["primitives"]))
        self.assertNotIn("big_loss_template:", "\n".join(plan["shared_evidence"]))

    def test_metadata_only_detector_overlap_does_not_attach_big_loss_or_promote_score(self) -> None:
        tool = _load_tool()
        exploit = {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace_path": str(self.ws),
            "angles": [
                _exploit_angle(
                    "angle-001",
                    "metadata overlap angle",
                    target_files=["AggregateVerifier.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect verifier proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
            ],
        }
        engage_report = (
            "# Engagement Report\n\n"
            "- Total hits: **1**\n"
            "- Distinct detectors: **1**\n"
            "- Analogical clusters: **1**\n\n"
            "## Clusters\n\n"
            "### Cluster: `metadata-detector` (1 hits)\n\n"
            f"- **[HIGH] `metadata-detector`** - `{self.ws}/AggregateVerifier.sol:42`\n"
            "  - snippet: `verify(proofType, proofData);`\n"
        )
        big_loss = {
            "manifests": [
                {
                    "composed_status": "composed",
                    "row_id": "BASE-SC-I01",
                    "template_id": "bridge_proof_domain",
                    "actor_sequence": [
                        {
                            "actor": "attacker",
                            "action": "submit forged proof",
                            "target": "AggregateVerifier.verify",
                            "evidence_required": "proof accepted",
                        }
                    ],
                }
            ]
        }
        _write_json(self.ws / ".auditooor" / "exploit_memory_brief.json", exploit)
        (self.ws / "engage_report.md").write_text(engage_report, encoding="utf-8")
        _write_json(self.ws / ".auditooor" / "big_loss_template_composed.json", big_loss)

        payload = tool.run(["--workspace", str(self.ws)])

        self.assertEqual(payload["summary"]["plan_count"], 1)
        plan = payload["plans"][0]
        self.assertEqual(plan["score"], 1)
        self.assertFalse(any(item["source_kind"] == "big_loss_actor_sequence" for item in plan["primitives"]))
        self.assertNotIn("big_loss_template:", "\n".join(plan["shared_evidence"]))

    def test_source_artifacts_with_shared_live_bridge_promote_distinct_signal(self) -> None:
        tool = _load_tool()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-LOCKED-BALANCE"
        producer = {
            "schema": "auditooor.exploit_queue_source_artifact.v1",
            "lead_id": "EQ-PRODUCER",
            "row_title": "producer state",
            "source_refs": [
                {"path": str(self.ws / "src" / "Vault.sol"), "line_start": 10, "line_end": 12}
            ],
            "state_evidence": {
                "lead_id": "EQ-PRODUCER",
                "role": "producer",
                "produces_state": ["vault_locked_balance"],
                "requires_state": [],
                "bridge_claims": [
                    {
                        "bridge_id": bridge_id,
                        "token": "vault_locked_balance",
                        "producer_lead_id": "EQ-PRODUCER",
                        "consumer_lead_id": "EQ-CONSUMER",
                        "source_refs": ["workspace:src/Vault.sol:10"],
                        "causal_bridge_signal": bridge_id,
                        "confidence": "source_cited_unexecuted",
                    }
                ],
            },
        }
        consumer = {
            "schema": "auditooor.exploit_queue_source_artifact.v1",
            "lead_id": "EQ-CONSUMER",
            "row_title": "consumer state",
            "source_refs": [
                {"path": str(self.ws / "src" / "Router.sol"), "line_start": 44, "line_end": 46}
            ],
            "state_evidence": {
                "lead_id": "EQ-CONSUMER",
                "role": "consumer",
                "produces_state": [],
                "requires_state": ["vault_locked_balance"],
                "bridge_claims": [
                    {
                        "bridge_id": bridge_id,
                        "token": "vault_locked_balance",
                        "producer_lead_id": "EQ-PRODUCER",
                        "consumer_lead_id": "EQ-CONSUMER",
                        "source_refs": ["workspace:src/Router.sol:44"],
                        "causal_bridge_signal": bridge_id,
                        "confidence": "source_cited_unexecuted",
                    }
                ],
            },
        }
        _write_json(artifact_dir / "EQ-PRODUCER.source_artifact.json", producer)
        _write_json(artifact_dir / "EQ-CONSUMER.source_artifact.json", consumer)

        payload = tool.run(["--workspace", str(self.ws)])

        self.assertEqual(payload["summary"]["source_artifact_state_evidence_count"], 2)
        self.assertEqual(payload["summary"]["plan_count"], 1)
        plan = payload["plans"][0]
        self.assertEqual(plan["causal_evidence_level"], "distinct_bridge_signal_present")
        self.assertFalse(plan["metadata_overlap_only"])
        self.assertIn(f"shared_live_rows:{bridge_id}", plan["shared_evidence"])
        self.assertIn("shared_causal_bridge_signals:live-locked-balance", plan["shared_evidence"])
        self.assertIn("live-locked-balance", plan["causal_bridge_signals"])
        self.assertIn(
            "source-evidence bridge is source-cited but unexecuted; no runnable chain proof is claimed",
            plan["blockers"],
        )
        self.assertEqual(plan["status"], "candidate_not_submit_ready")
        self.assertTrue(plan["candidate_not_submit_ready"])
        requirements = plan["composition_harness_requirements"]
        self.assertEqual(len(requirements), 1)
        requirement = requirements[0]
        self.assertEqual(requirement["binding_scope"], "composed_chain_harness")
        self.assertEqual(requirement["chain_id"], "CHAIN-001")
        self.assertEqual(requirement["producer_lead_id"], "EQ-PRODUCER")
        self.assertEqual(requirement["consumer_lead_id"], "EQ-CONSUMER")
        self.assertEqual(requirement["bridging_state"], "vault_locked_balance")
        self.assertIn("source-artifact:eq-producer", requirement["primitive_pair_ids"])
        self.assertIn("source-artifact:eq-consumer", requirement["primitive_pair_ids"])
        self.assertIn("producer_state_artifact", requirement)
        self.assertIn("consumer_entrypoint", requirement)
        self.assertIn("generated_test_path", requirement)
        self.assertIn("harness_command", requirement)
        self.assertIn("gating_test", requirement)
        self.assertTrue(all(item["source_kind"] == "source_artifact_state_evidence" for item in plan["primitives"]))

    def test_composed_source_artifacts_are_not_recomposed(self) -> None:
        tool = _load_tool()
        primitives = [
            {
                "source_kind": "source_artifact_state_evidence",
                "state_role": "producer_consumer",
                "paired_live_row_ids": ["LIVE-SHARED"],
                "causal_bridge_signals": ["live-shared"],
            },
            {
                "source_kind": "source_artifact_state_evidence",
                "state_role": "producer_consumer",
                "paired_live_row_ids": ["LIVE-SHARED"],
                "causal_bridge_signals": ["live-shared"],
            },
        ]

        self.assertEqual(tool._candidate_pair_indices(primitives), [])

    def test_direct_primitive_does_not_pair_with_composed_state_evidence(self) -> None:
        tool = _load_tool()
        primitives = [
            {
                "source_kind": "detector",
                "file_hints": ["src/Vault.sol"],
                "contract_hints": ["vault"],
                "attack_class_hints": ["accounting"],
                "proof_keys": [],
                "paired_live_row_ids": [],
                "paired_contracts": [],
                "causal_bridge_signals": [],
                "detector_slug": "accounting",
            },
            {
                "source_kind": "source_artifact_state_evidence",
                "state_role": "producer_consumer",
                "file_hints": ["src/Vault.sol"],
                "contract_hints": ["vault"],
                "attack_class_hints": ["accounting"],
                "proof_keys": ["vault_locked_balance"],
                "paired_live_row_ids": ["LIVE-SHARED"],
                "paired_contracts": [],
                "causal_bridge_signals": ["live-shared"],
            },
        ]

        self.assertEqual(tool._candidate_pair_indices(primitives), [])

    def test_duplicate_source_state_evidence_is_collapsed_before_pair_scan(self) -> None:
        tool = _load_tool()
        rows = []
        for idx in range(200):
            rows.append({
                "primitive_id": f"source-artifact:eq-{idx}",
                "lead_id": f"EQ-{idx}",
                "source_kind": "source_artifact_state_evidence",
                "title": f"EQ-{idx} state evidence",
                "state_role": "producer_consumer",
                "produces_state": ["shared_balance"],
                "requires_state": ["shared_balance"],
                "attack_class_hints": ["shared_balance"],
                "paired_live_row_ids": ["LIVE-SHARED"],
                "causal_bridge_signals": ["live-shared"],
            })
        collapsed = tool._dedupe_source_artifact_primitives(rows)
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0]["collapsed_source_artifact_count"], 200)
        self.assertEqual(len(collapsed[0]["collapsed_source_artifact_lead_ids"]), 8)

    def test_source_artifacts_emit_chain_synth_source_links_artifact(self) -> None:
        tool = _load_tool()
        driver = _load_driver()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-LOCKED-BALANCE"
        _write_json(
            artifact_dir / "EQ-PRODUCER.source_artifact.json",
            {
                "schema": "auditooor.exploit_queue_source_artifact.v1",
                "lead_id": "EQ-PRODUCER",
                "broken_invariant_ids": ["INV-A"],
                "target_template_ids": ["GCT-1"],
                "source_refs": [{"path": str(self.ws / "src" / "Vault.sol"), "line_start": 10}],
                "state_evidence": {
                    "lead_id": "EQ-PRODUCER",
                    "role": "producer",
                    "produces_state": ["vault_locked_balance"],
                    "requires_state": [],
                    "bridge_claims": [
                        {
                            "bridge_id": bridge_id,
                            "token": "vault_locked_balance",
                            "source_refs": ["workspace:src/Vault.sol:10"],
                            "causal_bridge_signal": bridge_id,
                        }
                    ],
                },
            },
        )
        _write_json(
            artifact_dir / "EQ-CONSUMER.source_artifact.json",
            {
                "schema": "auditooor.exploit_queue_source_artifact.v1",
                "lead_id": "EQ-CONSUMER",
                "broken_invariant_ids": ["INV-B"],
                "target_template_ids": ["GCT-1"],
                "source_refs": [{"path": str(self.ws / "src" / "Router.sol"), "line_start": 44}],
                "state_evidence": {
                    "lead_id": "EQ-CONSUMER",
                    "role": "consumer",
                    "produces_state": [],
                    "requires_state": ["vault_locked_balance"],
                    "bridge_claims": [
                        {
                            "bridge_id": bridge_id,
                            "token": "vault_locked_balance",
                            "source_refs": ["workspace:src/Router.sol:44"],
                            "causal_bridge_signal": bridge_id,
                        }
                    ],
                },
            },
        )

        plan_payload = tool.run(["--workspace", str(self.ws), "--emit-chain-synth-source-links"])

        sidecar = self.ws / ".auditooor" / "chain_synth_source_links.json"
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.chain_synth_source_links.v1")
        self.assertEqual(payload["workspace"], "<workspace>")
        self.assertEqual(payload["source_plan_artifact"], "swarm/chained_attack_plans.json")
        self.assertEqual(payload["links"], [])

        plan_payload["plans"][0]["executed_composition_proof"] = True
        bool_only_sidecar = tool._build_source_link_artifact(
            plan_payload,
            self.ws,
            "swarm/chained_attack_plans.json",
        )
        self.assertEqual(bool_only_sidecar["links"], [])
        plan_payload["plans"][0]["executed_composition_proof"] = {
            "status": "executed",
            "producer_lead_id": "EQ-PRODUCER",
            "consumer_lead_id": "EQ-CONSUMER",
            "from_source_refs": ["src/Vault.sol:10"],
            "to_source_refs": ["src/Router.sol:44"],
        }
        executed_sidecar = tool._build_source_link_artifact(
            plan_payload,
            self.ws,
            "swarm/chained_attack_plans.json",
        )
        _write_json(sidecar, executed_sidecar)
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(len(payload["links"]), 1)
        link = payload["links"][0]
        self.assertEqual(link["status"], "source_backed")
        self.assertEqual(link["broken_invariant_ids"], ["INV-A", "INV-B"])
        self.assertEqual(link["from_queue_lead_id"], "EQ-PRODUCER")
        self.assertEqual(link["to_queue_lead_id"], "EQ-CONSUMER")
        self.assertEqual(link["source_refs"], ["src/Vault.sol:10", "src/Router.sol:44"])
        self.assertEqual(link["from_source_refs"], ["src/Vault.sol:10"])
        self.assertEqual(link["to_source_refs"], ["src/Router.sol:44"])
        self.assertEqual(link["source_plan_artifact"], "swarm/chained_attack_plans.json")
        self.assertTrue(link["manual_seeding_absent"])
        self.assertTrue(link["source_artifacts_complete"])
        rows = driver.load_source_link_entries(self.ws, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["broken_invariant_ids"], ["INV-A", "INV-B"])
        self.assertEqual(rows[0]["from_queue_lead_id"], "EQ-PRODUCER")
        self.assertEqual(rows[0]["to_queue_lead_id"], "EQ-CONSUMER")
        self.assertEqual(rows[0]["source_plan_artifact"], "swarm/chained_attack_plans.json")

        queue_path = self.ws / driver.EXPLOIT_QUEUE_FILE
        existing_queue = {
            "schema": "auditooor.exploit_queue.v1",
            "queue": [
                {"lead_id": "EXISTING", "broken_invariant_ids": ["INV-UNCHANGED"]},
                {"lead_id": "EQ-PRODUCER", "broken_invariant_ids": ["INV-A"]},
                {"lead_id": "EQ-CONSUMER", "broken_invariant_ids": ["INV-B"]},
            ],
        }
        _write_json(queue_path, existing_queue)
        before_queue_bytes = queue_path.read_bytes()
        stale = (
            self.ws
            / ".auditooor"
            / f"chain_synthesis_{driver.datetime.now(driver.timezone.utc).strftime('%Y-%m-%d')}.json"
        )
        batch = self.ws / ".auditooor" / "batch.jsonl"
        batch.write_text(json.dumps({"task_id": "t1"}) + "\n", encoding="utf-8")
        templates = [
            {
                "chain_template_id": "GCT-1",
                "member_invariant_ids": ["INV-A", "INV-B"],
                "composition_breakdown": {"shared_commit_point_keywords": []},
            }
        ]
        argv = ["chain-synth-driver.py", "--workspace", str(self.ws), "--dry-run", "--json"]
        with mock.patch.object(
            driver,
            "call_vault_global_chain_template_match",
            return_value={"matched_templates": templates},
        ) as vault, mock.patch.object(
            driver, "build_batch_jsonl", return_value=batch
        ), mock.patch.object(
            driver, "dispatch_batch", return_value=[{"task_id": "t1"}]
        ), mock.patch.object(driver.sys, "argv", argv):
            rc = driver.main()

        self.assertEqual(rc, 0)
        vault.assert_called_once()
        self.assertEqual(queue_path.read_bytes(), before_queue_bytes)
        report = json.loads(stale.read_text(encoding="utf-8"))
        self.assertEqual(report["source_link_entries"], 1)
        self.assertEqual(report["advancing_chains"], 1)
        self.assertEqual(report["proof_obligations"], 1)
        proof_obligations = json.loads(
            (self.ws / driver.PROOF_OBLIGATIONS_FILE).read_text(encoding="utf-8")
        )
        edge = proof_obligations["obligations"][0]["source_backed_edges"][0]
        self.assertEqual(edge["from_queue_lead_id"], "EQ-PRODUCER")
        self.assertEqual(edge["to_queue_lead_id"], "EQ-CONSUMER")
        self.assertEqual(edge["from_source_refs"], ["src/Vault.sol:10"])
        self.assertEqual(edge["to_source_refs"], ["src/Router.sol:44"])
        self.assertTrue(edge["current_queue_verified"])
        self.assertEqual(edge["from_output"], "vault_locked_balance")
        self.assertEqual(edge["to_input"], "vault_locked_balance")

    def test_source_artifacts_skip_chain_synth_link_when_template_targets_disjoint(self) -> None:
        tool = _load_tool()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-DISJOINT-TEMPLATE"
        _write_json(
            artifact_dir / "EQ-PRODUCER.source_artifact.json",
            {
                "lead_id": "EQ-PRODUCER",
                "broken_invariant_ids": ["INV-A"],
                "target_template_ids": ["GCT-A"],
                "source_refs": [{"path": str(self.ws / "src" / "Vault.sol"), "line_start": 10}],
                "state_evidence": {
                    "lead_id": "EQ-PRODUCER",
                    "role": "producer",
                    "produces_state": ["locked"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Vault.sol:10"]}],
                },
            },
        )
        _write_json(
            artifact_dir / "EQ-CONSUMER.source_artifact.json",
            {
                "lead_id": "EQ-CONSUMER",
                "broken_invariant_ids": ["INV-B"],
                "target_template_ids": ["GCT-B"],
                "source_refs": [{"path": str(self.ws / "src" / "Router.sol"), "line_start": 44}],
                "state_evidence": {
                    "lead_id": "EQ-CONSUMER",
                    "role": "consumer",
                    "requires_state": ["locked"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Router.sol:44"]}],
                },
            },
        )

        tool.run(["--workspace", str(self.ws), "--emit-chain-synth-source-links"])

        sidecar = self.ws / ".auditooor" / "chain_synth_source_links.json"
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(payload["links"], [])

    def test_source_artifacts_skip_chain_synth_link_when_same_lead_id(self) -> None:
        tool = _load_tool()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-SAME-LEAD"
        _write_json(
            artifact_dir / "producer.source_artifact.json",
            {
                "lead_id": "EQ-SAME",
                "broken_invariant_ids": ["INV-A"],
                "target_template_ids": ["GCT-1"],
                "source_refs": [{"path": str(self.ws / "src" / "Vault.sol"), "line_start": 10}],
                "state_evidence": {
                    "lead_id": "EQ-SAME",
                    "role": "producer",
                    "produces_state": ["locked"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Vault.sol:10"]}],
                },
            },
        )
        _write_json(
            artifact_dir / "consumer.source_artifact.json",
            {
                "lead_id": "EQ-SAME",
                "broken_invariant_ids": ["INV-B"],
                "target_template_ids": ["GCT-1"],
                "source_refs": [{"path": str(self.ws / "src" / "Router.sol"), "line_start": 44}],
                "state_evidence": {
                    "lead_id": "EQ-SAME",
                    "role": "consumer",
                    "requires_state": ["locked"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Router.sol:44"]}],
                },
            },
        )

        tool.run(["--workspace", str(self.ws), "--emit-chain-synth-source-links"])

        sidecar = self.ws / ".auditooor" / "chain_synth_source_links.json"
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(payload["links"], [])

    def test_chain_synth_source_links_preserve_claim_string_file_line_refs(self) -> None:
        tool = _load_tool()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-CLAIM-REFS"
        _write_json(
            artifact_dir / "EQ-PRODUCER.source_artifact.json",
            {
                "schema": "auditooor.exploit_queue_source_artifact.v1",
                "lead_id": "EQ-PRODUCER",
                "broken_invariant_ids": ["INV-A"],
                "target_template_ids": ["GCT-1"],
                "state_evidence": {
                    "lead_id": "EQ-PRODUCER",
                    "role": "producer",
                    "produces_state": ["vault_locked_balance"],
                    "requires_state": [],
                    "bridge_claims": [
                        {
                            "bridge_id": bridge_id,
                            "source_refs": ["workspace:src/Vault.sol:10"],
                        }
                    ],
                },
            },
        )
        _write_json(
            artifact_dir / "EQ-CONSUMER.source_artifact.json",
            {
                "schema": "auditooor.exploit_queue_source_artifact.v1",
                "lead_id": "EQ-CONSUMER",
                "broken_invariant_ids": ["INV-B"],
                "target_template_ids": ["GCT-1"],
                "state_evidence": {
                    "lead_id": "EQ-CONSUMER",
                    "role": "consumer",
                    "produces_state": [],
                    "requires_state": ["vault_locked_balance"],
                    "bridge_claims": [
                        {
                            "bridge_id": bridge_id,
                            "source_refs": ["workspace:src/Router.sol:44"],
                        }
                    ],
                },
            },
        )

        plan_payload = tool.run(["--workspace", str(self.ws), "--emit-chain-synth-source-links"])

        sidecar = self.ws / ".auditooor" / "chain_synth_source_links.json"
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(payload["links"], [])
        plan_payload["plans"][0]["executed_composition_proof"] = {
            "status": "executed",
            "producer_lead_id": "EQ-PRODUCER",
            "consumer_lead_id": "EQ-CONSUMER",
            "from_source_refs": ["src/Vault.sol:10"],
            "to_source_refs": ["src/Router.sol:44"],
        }
        payload = tool._build_source_link_artifact(
            plan_payload,
            self.ws,
            "swarm/chained_attack_plans.json",
        )
        self.assertEqual(len(payload["links"]), 1)
        self.assertEqual(
            payload["links"][0]["source_refs"],
            ["src/Vault.sol:10", "src/Router.sol:44"],
        )

    def test_chain_synth_source_links_reject_weak_or_missing_composition_status_rows(self) -> None:
        tool = _load_tool()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-WEAK-STATUS"
        _write_json(
            artifact_dir / "EQ-PRODUCER.source_artifact.json",
            {
                "lead_id": "EQ-PRODUCER",
                "broken_invariant_ids": ["INV-A"],
                "source_refs": [{"path": str(self.ws / "src" / "Vault.sol"), "line_start": 10}],
                "state_evidence": {
                    "lead_id": "EQ-PRODUCER",
                    "role": "producer",
                    "produces_state": ["vault_locked_balance"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Vault.sol:10"]}],
                },
            },
        )
        _write_json(
            artifact_dir / "EQ-CONSUMER.source_artifact.json",
            {
                "lead_id": "EQ-CONSUMER",
                "broken_invariant_ids": ["INV-B"],
                "source_refs": [{"path": str(self.ws / "src" / "Router.sol"), "line_start": 44}],
                "state_evidence": {
                    "lead_id": "EQ-CONSUMER",
                    "role": "consumer",
                    "requires_state": ["vault_locked_balance"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Router.sol:44"]}],
                },
            },
        )

        plan_payload = tool.run(["--workspace", str(self.ws)])
        for proof_row in (
            {
                "producer_lead_id": "EQ-PRODUCER",
                "consumer_lead_id": "EQ-CONSUMER",
                "from_source_refs": ["src/Vault.sol:10"],
                "to_source_refs": ["src/Router.sol:44"],
            },
            {
                "status": "source_cited_unexecuted",
                "producer_lead_id": "EQ-PRODUCER",
                "consumer_lead_id": "EQ-CONSUMER",
                "from_source_refs": ["src/Vault.sol:10"],
                "to_source_refs": ["src/Router.sol:44"],
            },
        ):
            plan_payload["plans"][0]["composition_proof"] = proof_row
            payload = tool._build_source_link_artifact(
                plan_payload,
                self.ws,
                "swarm/chained_attack_plans.json",
            )
            self.assertEqual(payload["links"], [])

    def test_chain_synth_source_links_reject_advisory_blocked_dry_run_and_ref_free_rows(self) -> None:
        tool = _load_tool()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-BLOCKED-STATUS"
        _write_json(
            artifact_dir / "EQ-PRODUCER.source_artifact.json",
            {
                "lead_id": "EQ-PRODUCER",
                "broken_invariant_ids": ["INV-A"],
                "source_refs": [{"path": str(self.ws / "src" / "Vault.sol"), "line_start": 10}],
                "state_evidence": {
                    "lead_id": "EQ-PRODUCER",
                    "role": "producer",
                    "produces_state": ["vault_locked_balance"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Vault.sol:10"]}],
                },
            },
        )
        _write_json(
            artifact_dir / "EQ-CONSUMER.source_artifact.json",
            {
                "lead_id": "EQ-CONSUMER",
                "broken_invariant_ids": ["INV-B"],
                "source_refs": [{"path": str(self.ws / "src" / "Router.sol"), "line_start": 44}],
                "state_evidence": {
                    "lead_id": "EQ-CONSUMER",
                    "role": "consumer",
                    "requires_state": ["vault_locked_balance"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Router.sol:44"]}],
                },
            },
        )

        plan_payload = tool.run(["--workspace", str(self.ws)])
        base_row = {
            "status": "executed",
            "producer_lead_id": "EQ-PRODUCER",
            "consumer_lead_id": "EQ-CONSUMER",
            "from_source_refs": ["src/Vault.sol:10"],
            "to_source_refs": ["src/Router.sol:44"],
        }
        for proof_row in (
            {**base_row, "status": "advisory"},
            {**base_row, "status": "blocked"},
            {**base_row, "dry_run": True},
            {key: value for key, value in base_row.items() if key not in {"from_source_refs", "to_source_refs"}},
        ):
            plan_payload["plans"][0]["composition_proof"] = proof_row
            payload = tool._build_source_link_artifact(
                plan_payload,
                self.ws,
                "swarm/chained_attack_plans.json",
            )
            self.assertEqual(payload["links"], [])

        plan_payload["plans"][0]["composition_proof"] = base_row
        payload = tool._build_source_link_artifact(
            plan_payload,
            self.ws,
            "swarm/chained_attack_plans.json",
        )
        self.assertEqual(len(payload["links"]), 1)

    def test_chain_synth_source_links_reject_self_linking_proof_rows(self) -> None:
        tool = _load_tool()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-SELF-PROOF"
        _write_json(
            artifact_dir / "EQ-PRODUCER.source_artifact.json",
            {
                "lead_id": "EQ-PRODUCER",
                "broken_invariant_ids": ["INV-A"],
                "source_refs": [{"path": str(self.ws / "src" / "Vault.sol"), "line_start": 10}],
                "state_evidence": {
                    "lead_id": "EQ-PRODUCER",
                    "role": "producer",
                    "produces_state": ["vault_locked_balance"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Vault.sol:10"]}],
                },
            },
        )
        _write_json(
            artifact_dir / "EQ-CONSUMER.source_artifact.json",
            {
                "lead_id": "EQ-CONSUMER",
                "broken_invariant_ids": ["INV-B"],
                "source_refs": [{"path": str(self.ws / "src" / "Router.sol"), "line_start": 44}],
                "state_evidence": {
                    "lead_id": "EQ-CONSUMER",
                    "role": "consumer",
                    "requires_state": ["vault_locked_balance"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/Router.sol:44"]}],
                },
            },
        )

        plan_payload = tool.run(["--workspace", str(self.ws)])
        plan_payload["plans"][0]["composition_proof"] = {
            "status": "executed",
            "producer_lead_id": "EQ-PRODUCER",
            "consumer_lead_id": "EQ-PRODUCER",
            "from_source_refs": ["src/Vault.sol:10"],
            "to_source_refs": ["src/Router.sol:44"],
        }
        payload = tool._build_source_link_artifact(
            plan_payload,
            self.ws,
            "swarm/chained_attack_plans.json",
        )
        self.assertEqual(payload["links"], [])

    def test_chain_synth_source_links_out_arg_writes_custom_path(self) -> None:
        tool = _load_tool()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-CUSTOM-LINK"
        _write_json(
            artifact_dir / "EQ-A.source_artifact.json",
            {
                "lead_id": "EQ-A",
                "broken_invariant_ids": ["INV-A"],
                "source_refs": [{"path": str(self.ws / "src" / "A.sol"), "line_start": 1}],
                "state_evidence": {
                    "lead_id": "EQ-A",
                    "role": "producer",
                    "produces_state": ["x"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/A.sol:1"]}],
                },
            },
        )
        _write_json(
            artifact_dir / "EQ-B.source_artifact.json",
            {
                "lead_id": "EQ-B",
                "broken_invariant_ids": ["INV-B"],
                "source_refs": [{"path": str(self.ws / "src" / "B.sol"), "line_start": 2}],
                "state_evidence": {
                    "lead_id": "EQ-B",
                    "role": "consumer",
                    "requires_state": ["x"],
                    "bridge_claims": [{"bridge_id": bridge_id, "source_refs": ["workspace:src/B.sol:2"]}],
                },
            },
        )
        custom = self.ws / "custom_links.json"

        tool.run(["--workspace", str(self.ws), "--source-links-out", str(custom)])

        self.assertTrue(custom.exists())
        self.assertFalse((self.ws / ".auditooor" / "chain_synth_source_links.json").exists())
        payload = json.loads(custom.read_text(encoding="utf-8"))
        self.assertEqual(payload["links"], [])

    def test_chain_synth_source_links_skip_without_two_invariant_ids(self) -> None:
        tool = _load_tool()
        artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        bridge_id = "LIVE-NO-TWO-INV"
        for lead_id, source_file, line, role in (
            ("EQ-A", "A.sol", 1, "producer"),
            ("EQ-B", "B.sol", 2, "consumer"),
        ):
            _write_json(
                artifact_dir / f"{lead_id}.source_artifact.json",
                {
                    "lead_id": lead_id,
                    "broken_invariant_ids": ["INV-A"],
                    "source_refs": [{"path": str(self.ws / "src" / source_file), "line_start": line}],
                    "state_evidence": {
                        "lead_id": lead_id,
                        "role": role,
                        "produces_state": ["x"] if role == "producer" else [],
                        "requires_state": ["x"] if role == "consumer" else [],
                        "bridge_claims": [
                            {"bridge_id": bridge_id, "source_refs": [f"workspace:src/{source_file}:{line}"]}
                        ],
                    },
                },
            )

        tool.run(["--workspace", str(self.ws), "--emit-chain-synth-source-links"])

        sidecar = self.ws / ".auditooor" / "chain_synth_source_links.json"
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(payload["links"], [])

    def test_markdown_passes_precheck_and_missing_material_distinction_fails(self) -> None:
        tool = _load_tool()
        exploit = {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace_path": str(self.ws),
            "angles": [
                _exploit_angle(
                    "angle-001",
                    "withdraw accounting drift",
                    target_files=["src/Vault.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
                _exploit_angle(
                    "angle-002",
                    "cap desync",
                    target_files=["src/Vault.sol"],
                    proof_prerequisites=[
                        {
                            "artifact": ".auditooor/live_topology_proof_requirements.json",
                            "status": "required",
                            "summary": "collect proof pair",
                            "source_ref": "workspace:.auditooor/live_topology_proof_requirements.json",
                        }
                    ],
                ),
            ],
        }
        _write_json(self.ws / ".auditooor" / "exploit_memory_brief.json", exploit)

        payload = tool.run(["--workspace", str(self.ws)])
        markdown = self.ws / "swarm" / "chained_attack_plans.md"

        ok = subprocess.run(
            [sys.executable, str(PRECHECK), "--strict", str(markdown)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)

        broken = self.ws / "swarm" / "broken_chained_attack_plans.md"
        broken.write_text(
            markdown.read_text(encoding="utf-8").replace("- material distinction:", "- removed distinction:"),
            encoding="utf-8",
        )
        bad = subprocess.run(
            [sys.executable, str(PRECHECK), "--strict", str(broken)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
        payload = json.loads(bad.stdout)
        self.assertIn("material distinction from base issue", payload["missing_checks"])


if __name__ == "__main__":
    unittest.main()
