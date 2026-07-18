#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "v3-provider-source-collection-queue.py"
MAKEFILE = ROOT / "Makefile"


def _load_tool():
    spec = importlib.util.spec_from_file_location("v3_provider_source_collection_queue", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_registry(root: Path) -> Path:
    path = root / "reference" / "external_intel_sources.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
schema: auditooor.external_intel_sources.v1
sources:
  - source_id: defillama_hacks_tvl
    url_or_api: https://api.llama.fi/hacks
    miner:
      tool_path: tools/hackerman-etl-from-post-mortem.py
      makefile_target: hackerman-etl-post-mortem
      mode: post_mortem_api
      auth_env: []
    cursor:
      path: .auditooor/external_intel_cursors/defillama.json
      field: newest_incident_date
    ttl: 24h
    output_subtree: audit/corpus_tags/tags/defillama_hacks_delta
    quality_gate:
      required_fields:
        - protocol
        - incident_date
      reject_if:
        - amount_only_without_mechanics
      minimum_verification_tier: tier-3-public-index
    promotion_target:
      downstream:
        - incident_backfill_queue
  - source_id: darknavy_web3_pages
    url_or_api:
      - https://www.darknavy.org/web3/
    miner:
      tool_path: tools/hackerman-etl-from-darknavy-web3.py
      makefile_target: darknavy-web3-mine
      mode: paginated_web
      auth_env: []
    cursor:
      path: .auditooor/external_intel_cursors/darknavy_web3.json
      field: newest_report
    ttl: 24h
    output_subtree: audit/corpus_tags/tags/darknavy_web3_incidents
    quality_gate:
      required_fields:
        - title
        - report_date
        - attacker_action_sequence
      reject_if:
        - missing_report_body
      minimum_verification_tier: tier-2-verified-public-archive
    promotion_target:
      downstream:
        - detector_seed_queue
  - source_id: defimon_delta_blocked_no_live_source
    url_or_api: https://t.me/s/defimon_alerts
    miner:
      tool_path: tools/defimon-staleness-check.py
      makefile_target: defimon-staleness-check
      mode: public_mirror_manual_delta
      auth_env: []
    cursor:
      path: .auditooor/external_intel_cursors/defimon.json
      field: newest_post_id
    ttl: 24h
    output_subtree: audit/corpus_tags/tags/defimon_delta
    quality_gate:
      required_fields:
        - source_url
        - post_id
      reject_if:
        - negotiation_message_without_mechanics
      minimum_verification_tier: tier-3-public-index
    promotion_target:
      downstream:
        - detector_seed_queue
  - source_id: verus_bridge_incident_2026_05
    url_or_api:
      - https://www.halborn.com/blog/post/explained-the-verus-ethereum-bridge-hack-may-2026
    miner:
      tool_path: tools/external-intel-refresh.py
      mode: single_incident_fetch
      auth_env: []
    cursor:
      path: .auditooor/external_intel_cursors/verus_bridge_2026_05.json
      field: incident_status
    ttl: 12h
    output_subtree: audit/corpus_tags/tags/bridge_incidents/verus_bridge_2026_05
    quality_gate:
      required_fields:
        - root_cause
      minimum_verification_tier: tier-2-verified-public-archive
    promotion_target:
      downstream:
        - bridge_incident_case_study
  - source_id: map_butter_bridge_incident_2026_05
    url_or_api:
      - https://etherscan.io/tx/0x31e56b4737649e0acdb0ebb4eca44d16aeca25f60c022cbde85f092bde27664a
    miner:
      tool_path: tools/external-intel-refresh.py
      mode: single_incident_fetch
      auth_env: []
    cursor:
      path: .auditooor/external_intel_cursors/map_butter_bridge_2026_05.json
      field: incident_status
    ttl: 12h
    output_subtree: audit/corpus_tags/tags/bridge_incidents/map_butter_bridge_2026_05
    quality_gate:
      required_fields:
        - root_cause
      minimum_verification_tier: tier-2-verified-public-archive
    promotion_target:
      downstream:
        - bridge_incident_case_study
""",
        encoding="utf-8",
    )
    return path


def write_result(root: Path) -> Path:
    path = root / ".auditooor" / "provider_fanout" / "demo" / "runs" / "run" / "v3_provider_local_verification_result.json"
    write_json(
        path,
        {
            "schema": "auditooor.v3_provider_local_verification_result.v1",
            "campaign_id": "demo",
            "run_id": "run",
            "rows": [
                {
                    "queue_id": "V3-LV-001",
                    "row_id": "row-1",
                    "task_id": "kimi-defillama",
                    "provider": "kimi",
                    "model": "kimi-for-coding",
                    "route": "external_source_needed",
                    "verification_status": "needs_more_source",
                    "terminal_outcome": "needs_more_source",
                    "source_collection_required": True,
                    "claim": {
                        "kind": "proof_obligation",
                        "provider_claim_id": "c1",
                        "summary": "Need DefiLlama primary source URL and incident date.",
                    },
                    "source_provider_row": {
                        "provider_output_path": str(root / "provider.out.txt"),
                        "template": "source-extract",
                    },
                    "verification": {
                        "commands": ["collect primary URL/date/txhash or local source artifact"],
                    },
                    "source_ref_checks": [{"path": f"source-{idx}.md"} for idx in range(12)],
                    "grep_hits": [{"path": "source-0.md", "line": idx} for idx in range(12)],
                },
                {
                    "queue_id": "V3-LV-002",
                    "row_id": "row-2",
                    "task_id": "kimi-defillama-dup",
                    "provider": "kimi",
                    "model": "kimi-for-coding",
                    "route": "external_source_needed",
                    "verification_status": "needs_more_source",
                    "terminal_outcome": "needs_more_source",
                    "source_collection_required": True,
                    "claim": {
                        "kind": "proof_obligation",
                        "provider_claim_id": "c2",
                        "summary": "Need DefiLlama primary source URL and incident date.",
                    },
                    "source_provider_row": {"template": "source-extract"},
                    "verification": {"commands": []},
                },
                {
                    "queue_id": "V3-LV-003",
                    "row_id": "row-3",
                    "task_id": "minimax-ok",
                    "provider": "minimax",
                    "model": "MiniMax-M2.7",
                    "route": "kill_review",
                    "verification_status": "verified",
                    "terminal_outcome": "verified_no_action",
                    "claim": {"kind": "kill_reason", "summary": "Already terminal."},
                },
                {
                    "queue_id": "V3-LV-004",
                    "row_id": "row-4",
                    "task_id": "minimax-needs-judgment",
                    "provider": "minimax",
                    "model": "MiniMax-M2.7",
                    "route": "kill_review",
                    "verification_status": "verified",
                    "terminal_outcome": None,
                    "terminal_safe": False,
                    "terminal_judgment_required": True,
                    "terminal_outcome_options": ["verified_no_action", "rejected_oos"],
                    "claim": {
                        "kind": "kill_reason",
                        "provider_claim_id": "kill-1",
                        "summary": "Exact contradiction exists but needs local terminal judgment.",
                    },
                    "verification": {
                        "evidence_refs": [{"kind": "local_file", "path": "tools/example.py", "verified": True}],
                    },
                    "grep_hits": [{"path": "tools/example.py", "line": 12, "pattern": "contradiction"}],
                },
            ],
        },
    )
    return path


class V3ProviderSourceCollectionQueueTests(unittest.TestCase):
    def test_build_queue_groups_needs_more_source_with_registry_context(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = write_registry(root)
            result = write_result(root)

            payload = mod.build_queue(root, [result], registry)

            self.assertEqual(payload["summary"]["source_rows"], 2)
            self.assertEqual(payload["summary"]["deduped_items"], 1)
            item = payload["items"][0]
            self.assertEqual(item["source_family"], "defillama")
            self.assertEqual(item["packet_kind"], "source_collection")
            self.assertEqual(item["review_lanes"], ["local", "kimi"])
            self.assertEqual(item["lane_assignments"]["kimi"], "source_extraction")
            self.assertEqual(item["registry"]["source_id"], "defillama_hacks_tvl")
            self.assertIn("hackerman-etl-post-mortem SOURCE=defillama", item["next_command"])
            self.assertEqual(len(item["rows"]), 2)
            self.assertLessEqual(len(item["rows"][0]["source_ref_checks"]), 8)
            self.assertLessEqual(len(item["rows"][0]["grep_hits"]), 8)
            self.assertEqual(payload["summary"]["by_source_reviewer"], {"kimi": 2, "local": 2})
            self.assertFalse(payload["promotion_authority"])

    def test_result_discovery_prefers_current_campaign_gate_verification(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            current = (
                root
                / ".auditooor"
                / "provider_fanout"
                / "cam"
                / "runs"
                / "current"
                / "v3_provider_local_verification_result.json"
            )
            stale = (
                root
                / ".auditooor"
                / "provider_fanout"
                / "cam"
                / "runs"
                / "stale"
                / "v3_provider_local_verification_result.json"
            )
            write_json(current, {"schema": "auditooor.v3_provider_local_verification_result.v1", "rows": []})
            write_json(stale, {"schema": "auditooor.v3_provider_local_verification_result.v1", "rows": []})
            write_json(
                root / ".auditooor" / "provider_campaign_completeness_gate.json",
                {"artifacts": {"local_verification": str(current)}},
            )

            self.assertEqual(mod._result_paths(root, []), [current.resolve()])

    def test_result_discovery_can_include_all_results_despite_gate_artifact(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            current = (
                root
                / ".auditooor"
                / "provider_fanout"
                / "cam"
                / "runs"
                / "current"
                / "v3_provider_local_verification_result.json"
            )
            other = (
                root
                / ".auditooor"
                / "provider_fanout"
                / "followup"
                / "runs"
                / "other"
                / "v3_provider_local_verification_result.json"
            )
            write_json(current, {"schema": "auditooor.v3_provider_local_verification_result.v1", "rows": []})
            write_json(other, {"schema": "auditooor.v3_provider_local_verification_result.v1", "rows": []})
            write_json(
                root / ".auditooor" / "provider_campaign_completeness_gate.json",
                {"artifacts": {"local_verification": str(current)}},
            )

            self.assertEqual(mod._result_paths(root, []), [current.resolve()])
            self.assertEqual(mod._result_paths(root, [], include_all_results=True), [current.resolve(), other.resolve()])

    def test_defimon_wins_mixed_solodit_defimon_family_routing(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = write_registry(root)
            result = root / ".auditooor" / "provider_fanout" / "demo" / "runs" / "run" / "defimon.json"
            write_json(
                result,
                {
                    "schema": "auditooor.v3_provider_local_verification_result.v1",
                    "rows": [
                        {
                            "queue_id": "V3-LV-DEFIMON",
                            "row_id": "row-defimon",
                            "task_id": "kimi-04-solodit-defimon-deltas",
                            "provider": "kimi",
                            "model": "kimi-for-coding",
                            "route": "external_source_needed",
                            "verification_status": "needs_more_source",
                            "terminal_outcome": "needs_more_source",
                            "source_collection_required": True,
                            "claim": {
                                "kind": "corpus_gap",
                                "provider_claim_id": "defimon-mixed",
                                "summary": "Solodit and Defimon delta extraction need Defimon primary post confirmation.",
                            },
                        }
                    ],
                },
            )

            payload = mod.build_queue(root, [result], registry)

            item = payload["items"][0]
            self.assertEqual(item["source_family"], "defimon")
            self.assertEqual(item["registry"]["source_id"], "defimon_delta_blocked_no_live_source")
            self.assertIn("defimon-nextjs-blog-miner.py", item["next_command"])
            self.assertIn("--max-posts 12 --json-only", item["next_command"])

    def test_minimax_source_rows_get_adversarial_kill_lane(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = write_registry(root)
            result = root / ".auditooor" / "provider_fanout" / "demo" / "runs" / "run" / "minimax-source.json"
            write_json(
                result,
                {
                    "schema": "auditooor.v3_provider_local_verification_result.v1",
                    "rows": [
                        {
                            "queue_id": "V3-LV-MM",
                            "row_id": "row-mm",
                            "task_id": "minimax-solodit-source",
                            "provider": "minimax",
                            "model": "MiniMax-M2.7",
                            "route": "external_source_needed",
                            "verification_status": "needs_more_source",
                            "terminal_outcome": "needs_more_source",
                            "source_collection_required": True,
                            "claim": {
                                "kind": "kill_reason",
                                "provider_claim_id": "mm-solodit",
                                "summary": "Need Solodit primary source before accepting or killing this claim.",
                            },
                        }
                    ],
                },
            )

            payload = mod.build_queue(root, [result], registry)

            item = payload["items"][0]
            self.assertEqual(item["source_family"], "solodit")
            self.assertEqual(item["review_lanes"], ["local", "kimi", "minimax"])
            self.assertEqual(item["lane_assignments"]["kimi"], "source_extraction")
            self.assertEqual(item["lane_assignments"]["minimax"], "adversarial_kill")

    def test_build_queue_adds_terminal_judgment_packets(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = write_registry(root)
            result = write_result(root)

            payload = mod.build_queue(root, [result], registry)

            self.assertEqual(payload["summary"]["terminal_judgment_rows"], 1)
            self.assertEqual(payload["summary"]["terminal_judgment_items"], 1)
            self.assertEqual(payload["summary"]["by_terminal_family"], {"kill_review": 1})
            item = payload["terminal_judgment_items"][0]
            self.assertEqual(item["schema"], "auditooor.v3_provider_terminal_judgment_packet.v1")
            self.assertEqual(item["judgment_family"], "kill_review")
            self.assertEqual(item["review_lanes"], ["local", "minimax"])
            self.assertEqual(item["terminal_state"], "needs_local_judgment")
            self.assertIn("local_terminal_outcome_required", item["promotion_blockers"])
            row = item["rows"][0]
            self.assertEqual(row["queue_id"], "V3-LV-004")
            self.assertEqual(row["required_local_decision"], "select_terminal_outcome_or_keep_pending")
            self.assertEqual(row["terminal_outcome_options"], ["verified_no_action", "rejected_oos"])

    def test_darknavy_rows_use_live_miner_not_planner(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = write_registry(root)
            result = root / ".auditooor" / "provider_fanout" / "demo" / "runs" / "run" / "darknavy.json"
            write_json(
                result,
                {
                    "schema": "auditooor.v3_provider_local_verification_result.v1",
                    "rows": [
                        {
                            "queue_id": "V3-LV-DARKNAVY",
                            "row_id": "row-darknavy",
                            "task_id": "kimi-darknavy-source",
                            "provider": "kimi",
                            "model": "kimi-for-coding",
                            "route": "external_source_needed",
                            "verification_status": "needs_more_source",
                            "terminal_outcome": "needs_more_source",
                            "source_collection_required": True,
                            "claim": {
                                "kind": "proof_obligation",
                                "provider_claim_id": "darknavy-c1",
                                "summary": "Need Darknavy exploit article source packet.",
                            },
                        }
                    ],
                },
            )

            payload = mod.build_queue(root, [result], registry)

            self.assertEqual(payload["summary"]["deduped_items"], 1)
            item = payload["items"][0]
            self.assertEqual(item["source_family"], "darknavy")
            self.assertEqual(item["registry"]["source_id"], "darknavy_web3_pages")
            self.assertIn("make darknavy-web3-mine", item["next_command"])
            self.assertIn("FETCH=1", item["next_command"])
            self.assertIn("APPLY=1", item["next_command"])
            self.assertNotIn("darknavy-web3-plan", item["next_command"])

    def test_bridge_single_incident_rows_use_external_intel_without_kimi_lane(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = write_registry(root)
            result = root / ".auditooor" / "provider_fanout" / "demo" / "runs" / "run" / "bridge-source.json"
            write_json(
                result,
                {
                    "schema": "auditooor.v3_provider_local_verification_result.v1",
                    "rows": [
                        {
                            "queue_id": "V3-LV-VERUS",
                            "row_id": "row-verus",
                            "task_id": "kimi-verus-source",
                            "provider": "kimi",
                            "route": "external_source_needed",
                            "verification_status": "needs_more_source",
                            "terminal_outcome": "needs_more_source",
                            "source_collection_required": True,
                            "claim": {
                                "kind": "proof_obligation",
                                "summary": "Need Verus bridge root-cause source collection.",
                            },
                        },
                        {
                            "queue_id": "V3-LV-MAP",
                            "row_id": "row-map",
                            "task_id": "minimax-map-butter-source",
                            "provider": "minimax",
                            "route": "external_source_needed",
                            "verification_status": "needs_more_source",
                            "terminal_outcome": "needs_more_source",
                            "source_collection_required": True,
                            "claim": {
                                "kind": "proof_obligation",
                                "summary": "Need MAP/Butter Bridge MAPO OmniServiceProxy root-cause source collection.",
                            },
                        },
                    ],
                },
            )

            payload = mod.build_queue(root, [result], registry)

            items = {item["source_family"]: item for item in payload["items"]}
            self.assertEqual(items["verus"]["registry"]["source_id"], "verus_bridge_incident_2026_05")
            self.assertEqual(items["verus"]["review_lanes"], ["local"])
            self.assertIn("make external-intel-refresh SOURCE=verus_bridge_incident_2026_05", items["verus"]["next_command"])
            self.assertIn("FETCH_SINGLE_INCIDENT=1", items["verus"]["next_command"])
            self.assertNotIn("kimi", items["verus"]["review_lanes"])
            self.assertEqual(items["map_butter"]["registry"]["source_id"], "map_butter_bridge_incident_2026_05")
            self.assertEqual(items["map_butter"]["review_lanes"], ["local", "minimax"])
            self.assertIn(
                "make external-intel-refresh SOURCE=map_butter_bridge_incident_2026_05",
                items["map_butter"]["next_command"],
            )
            self.assertIn("FETCH_SINGLE_INCIDENT=1", items["map_butter"]["next_command"])
            self.assertNotIn("kimi", items["map_butter"]["review_lanes"])

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = write_registry(root)
            result = write_result(root)
            out_json = root / "queue.json"
            out_md = root / "queue.md"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--registry",
                    str(registry),
                    "--result",
                    str(result),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--json",
                ],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["deduped_items"], 1)
            self.assertEqual(payload["summary"]["terminal_judgment_items"], 1)
            self.assertTrue(out_json.is_file())
            self.assertIn("V3 Provider Source Collection Queue", out_md.read_text(encoding="utf-8"))
            self.assertIn("Terminal Judgment Packets", out_md.read_text(encoding="utf-8"))

    def test_makefile_exposes_target(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("v3-provider-source-collection-queue:", text)
        self.assertIn("v3-provider-closure-queue:", text)
        self.assertIn("--include-all-results", text)
        self.assertIn("v3-provider-source-collection-queue-test:", text)


if __name__ == "__main__":
    unittest.main()
