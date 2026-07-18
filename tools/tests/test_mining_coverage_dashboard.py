#!/usr/bin/env python3
"""Tests for tools/mining-coverage-dashboard.py.

All tests use tiny temp fixtures. They do not scan the repository's real corpus
trees or raw mined report bodies.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "mining-coverage-dashboard.py"


def _load_tool() -> Any:
    spec = importlib.util.spec_from_file_location("mining_coverage_dashboard", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mining_coverage_dashboard"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


NOW = datetime(2026, 5, 20, tzinfo=timezone.utc)


def _write_registry(root: Path) -> Path:
    registry = root / "reference" / "external_intel_sources.yaml"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(
        """
schema: auditooor.external_intel_sources.v1
sources:
  - source_id: solodit_high_plus_findings
    name: Solodit high-plus findings delta
    miner:
      tool_path: tools/solodit-rest-direct.py
      mode: rest_api
    cursor:
      type: monotonic_finding_id
      path: reference/solodit_ingest_cursor.json
      field: last_id
    ttl: 24h
    output_subtree: audit/corpus_tags/tags/solodit_delta
    network_requirement:
      required: true
  - source_id: pashov_public_audits
    name: Pashov Audit Group public reports
    miner:
      tool_path: tools/hackerman-etl-from-audit-firm-pdf-pashov.py
      mode: github_pdf_listing
    cursor:
      type: git_commit
      path: .auditooor/external_intel_cursors/pashov_public_audits.json
      field: last_seen_commit
    ttl: 14d
    output_subtree: audit/corpus_tags/tags/audit_firm_findings_pashov
    network_requirement:
      required: false
  - source_id: defillama_hacks_tvl
    name: DefiLlama hacks and total value lost feed
    miner:
      tool_path: tools/external-intel-refresh.py
      mode: web_or_api_backlog
    cursor:
      type: newest_incident_date
      path: .auditooor/external_intel_cursors/defillama_hacks.json
      field: newest_incident_date
    ttl: 24h
    output_subtree: audit/corpus_tags/tags/defillama_hacks_delta
    network_requirement:
      required: true
  - source_id: rekt_news_incidents
    name: Rekt-style public incident writeups
    miner:
      tool_path: tools/external-intel-refresh.py
      mode: web_backlog
    ttl: 48h
    output_subtree: audit/corpus_tags/tags/rekt_news_incidents
    network_requirement:
      required: true
  - source_id: darknavy_web3_pages
    name: DARKNAVY Web3 exploit analysis pages
    miner:
      tool_path: tools/external-intel-refresh.py
      mode: paginated_web_backlog
    ttl: 24h
    output_subtree: audit/corpus_tags/tags/darknavy_web3_incidents
    network_requirement:
      required: true
  - source_id: defimon_delta_blocked_no_live_source
    name: Defimon delta mining blocked source row
    miner:
      tool_path: tools/external-intel-refresh.py
      mode: blocked_no_live_source
    cursor:
      type: blocked_no_live_source
      path: .auditooor/external_intel_cursors/defimon.json
      field: status
    ttl: 7d
    output_subtree: audit/corpus_tags/tags/defimon_delta
    status: BLOCKED_NO_LIVE_SOURCE
    backlog_reason: Prior Defimon records exist, but live source/API is not codified.
""".lstrip(),
        encoding="utf-8",
    )
    return registry


def _write_record(base: Path, name: str = "record.json") -> None:
    base.mkdir(parents=True, exist_ok=True)
    (base / name).write_text(json.dumps({"record_id": "r1"}), encoding="utf-8")


class MiningCoverageDashboardTests(unittest.TestCase):
    def test_build_dashboard_classifies_fresh_stale_missing_and_backlog(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = _write_registry(root)
            tags = root / "audit" / "corpus_tags" / "tags"
            corpus_mined = root / "reference" / "corpus_mined"
            corpus_mined.mkdir(parents=True)
            (corpus_mined / "slice_aa.md").write_text("# slice\n", encoding="utf-8")

            solodit_cursor = root / "reference" / "solodit_ingest_cursor.json"
            solodit_cursor.write_text(
                json.dumps({"updated_at": "2026-05-19T12:00:00+00:00", "last_id": 123}),
                encoding="utf-8",
            )
            _write_record(tags / "solodit_delta" / "case-a")

            pashov_cursor = root / ".auditooor" / "external_intel_cursors" / "pashov_public_audits.json"
            pashov_cursor.parent.mkdir(parents=True, exist_ok=True)
            pashov_cursor.write_text(
                json.dumps({"updated_at": "2026-04-01T00:00:00+00:00", "last_seen_commit": "abc"}),
                encoding="utf-8",
            )
            _write_record(tags / "audit_firm_findings_pashov" / "case-b", "record.yaml")
            old_ts = datetime(2026, 4, 1, tzinfo=timezone.utc).timestamp()
            os.utime(tags / "audit_firm_findings_pashov" / "case-b" / "record.yaml", (old_ts, old_ts))

            artifact_report = root / "agent_artifact_mining_report.json"
            artifact_report.write_text(
                json.dumps(
                    {
                        "generated_at": "2026-05-20T00:00:00+00:00",
                        "total_artifacts": 3,
                        "artifact_type_counts": {"candidate_detector_pattern": 2},
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_dashboard(
                root=root,
                external_sources_path=registry,
                corpus_mined_path=corpus_mined,
                tags_dir=tags,
                agent_reports=[artifact_report],
                now=NOW,
            )

        rows = {row["source_id"]: row for row in payload["rows"]}
        self.assertEqual(payload["schema"], tool.SCHEMA_VERSION)
        self.assertEqual(rows["solodit_high_plus_findings"]["status"], "fresh")
        self.assertEqual(rows["solodit_high_plus_findings"]["mined_record_count"], 1)
        self.assertEqual(rows["solodit_high_plus_findings"]["cursor_value"], 123)
        self.assertEqual(rows["pashov_public_audits"]["status"], "stale")
        self.assertEqual(rows["defillama_hacks_tvl"]["status"], "backlog")
        self.assertEqual(rows["rekt_news_incidents"]["status"], "backlog")
        self.assertEqual(rows["darknavy_web3_pages"]["status"], "backlog")
        self.assertEqual(rows["defimon_delta_blocked_no_live_source"]["status"], "backlog")
        self.assertEqual(rows["reference_corpus_mined"]["status"], "fresh")
        self.assertEqual(rows["agent_artifact_mining_report"]["mined_record_count"], 3)
        self.assertGreaterEqual(payload["summary"]["backlog"], 4)
        self.assertEqual(payload["summary"]["stale"], 1)

    def test_missing_rows_when_no_local_outputs_exist(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "external_intel_sources.yaml"
            registry.parent.mkdir(parents=True)
            registry.write_text(
                """
sources:
  - source_id: solodit_high_plus_findings
    miner:
      tool_path: tools/solodit-rest-direct.py
      mode: rest_api
    cursor:
      path: reference/solodit_ingest_cursor.json
      field: last_id
    ttl: 24h
    output_subtree: audit/corpus_tags/tags/solodit_delta
""".lstrip(),
                encoding="utf-8",
            )
            payload = tool.build_dashboard(
                root=root,
                external_sources_path=registry,
                corpus_mined_path=root / "reference" / "corpus_mined",
                tags_dir=root / "audit" / "corpus_tags" / "tags",
                agent_reports=[],
                now=NOW,
            )

        rows = {row["source_id"]: row for row in payload["rows"]}
        self.assertEqual(rows["solodit_high_plus_findings"]["status"], "missing")
        self.assertEqual(rows["reference_corpus_mined"]["status"], "missing")
        self.assertEqual(rows["agent_artifact_mining_report"]["status"], "missing")
        self.assertEqual(payload["summary"]["missing"], 3)

    def test_nested_source_specific_record_pairs_count_by_record_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = _write_registry(root)
            out = root / "audit" / "corpus_tags" / "tags" / "darknavy_web3_incidents"
            incident = out / "incident-a"
            incident.mkdir(parents=True)
            payload = {
                "schema": "auditooor.darknavy_web3_record.v1",
                "record_id": "darknavy-web3:incident-a:abc",
                "record_source_url": "https://www.darknavy.org/web3/exploits/incident-a/",
            }
            (incident / "high-abc.json").write_text(json.dumps(payload), encoding="utf-8")
            (incident / "high-abc.yaml").write_text(
                "\n".join(
                    [
                        "schema: auditooor.darknavy_web3_record.v1",
                        "record_id: darknavy-web3:incident-a:abc",
                        "record_source_url: https://www.darknavy.org/web3/exploits/incident-a/",
                    ]
                ),
                encoding="utf-8",
            )

            dashboard = tool.build_dashboard(
                root=root,
                external_sources_path=registry,
                corpus_mined_path=root / "reference" / "corpus_mined",
                tags_dir=root / "audit" / "corpus_tags" / "tags",
                agent_reports=[],
                now=NOW,
            )

        rows = {row["source_id"]: row for row in dashboard["rows"]}
        self.assertEqual(rows["darknavy_web3_pages"]["mined_record_count"], 1)
        self.assertEqual(rows["darknavy_web3_pages"]["mined_file_count"], 2)

    def test_defihacklabs_registry_row_uses_local_corpus_signal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "external_intel_sources.yaml"
            registry.parent.mkdir(parents=True)
            registry.write_text(
                """
sources:
  - source_id: defihacklabs_foundry_pocs
    miner:
      tool_path: tools/defihacklabs-to-specs.py
      mode: git_tree
    cursor:
      path: .auditooor/external_intel_cursors/defihacklabs.json
      field: last_seen_commit
    ttl: 7d
    output_subtree: audit/corpus_tags/tags/defihacklabs_delta
""".lstrip(),
                encoding="utf-8",
            )
            catalog = root / "reference" / "corpus_mined" / "defihacklabs_catalog.md"
            catalog.parent.mkdir(parents=True)
            catalog.write_text("# DeFiHackLabs catalog\n", encoding="utf-8")
            patterns = root / "reference" / "patterns.dsl"
            patterns.mkdir(parents=True)
            (patterns / "dh-router-arbitrary-target-with-approval-pool.yaml").write_text(
                "id: dh-router-arbitrary-target-with-approval-pool\n",
                encoding="utf-8",
            )

            payload = tool.build_dashboard(
                root=root,
                external_sources_path=registry,
                corpus_mined_path=root / "reference" / "corpus_mined",
                tags_dir=root / "audit" / "corpus_tags" / "tags",
                agent_reports=[],
                now=NOW,
            )

        row = {row["source_id"]: row for row in payload["rows"]}["defihacklabs_foundry_pocs"]
        self.assertEqual(row["status"], "fresh")
        self.assertEqual(row["local_pattern_file_count"], 2)
        self.assertEqual(row["mined_file_count"], 2)
        self.assertIsNotNone(row["last_mined_at"])

    def test_stale_source_with_refs_is_queued_not_blocking_stale(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "external_intel_sources.yaml"
            registry.parent.mkdir(parents=True)
            registry.write_text(
                """
sources:
  - source_id: solodit_high_plus_findings
    name: Solodit high-plus findings delta
    url_or_api: https://solodit.cyfrin.io/api/v1/solodit/findings
    source_refs:
      - https://docs.solodit.cyfrin.io/
    miner:
      tool_path: tools/solodit-rest-direct.py
      mode: rest_api
    cursor:
      path: reference/solodit_ingest_cursor.json
      field: last_id
    ttl: 24h
    output_subtree: audit/corpus_tags/tags/solodit_delta
    network_requirement:
      required: true
""".lstrip(),
                encoding="utf-8",
            )
            tool_file = root / "tools" / "solodit-rest-direct.py"
            tool_file.parent.mkdir(parents=True)
            tool_file.write_text("# solodit miner\n", encoding="utf-8")
            cursor = root / "reference" / "solodit_ingest_cursor.json"
            cursor.write_text(
                json.dumps({"updated_at": "2026-05-10T00:00:00+00:00", "last_id": 123}),
                encoding="utf-8",
            )

            payload = tool.build_dashboard(
                root=root,
                external_sources_path=registry,
                corpus_mined_path=root / "reference" / "corpus_mined",
                tags_dir=root / "audit" / "corpus_tags" / "tags",
                agent_reports=[],
                now=NOW,
            )

        row = {row["source_id"]: row for row in payload["rows"]}["solodit_high_plus_findings"]
        self.assertEqual(row["status"], "queued")
        self.assertEqual(payload["summary"]["queued"], 1)
        self.assertEqual(payload["summary"]["stale"], 0)
        self.assertIn("https://docs.solodit.cyfrin.io/", row["source_refs"])
        self.assertEqual(row["queue_target"], "python3 tools/solodit-rest-direct.py")

    def test_alternate_cursors_and_output_globs_count_language_refreshes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "external_intel_sources.yaml"
            registry.parent.mkdir(parents=True)
            registry.write_text(
                """
sources:
  - source_id: solodit_high_plus_findings
    miner:
      tool_path: tools/solodit-rest-direct.py
      mode: rest_api
    cursor:
      path: reference/solodit_ingest_cursor.json
      alternate_paths:
        - reference/solodit_ingest_cursor_rust.json
        - reference/solodit_ingest_cursor_go.json
      field: last_id
    ttl: 24h
    output_subtree: audit/corpus_tags/tags/solodit_freshness_backfill_<date>
    output_subtree_globs:
      - audit/corpus_tags/tags/solodit_*_backfill_20260520
""".lstrip(),
                encoding="utf-8",
            )
            (root / "reference" / "solodit_ingest_cursor.json").write_text(
                json.dumps({"updated_at": "2026-05-10T00:00:00+00:00", "last_id": 1}),
                encoding="utf-8",
            )
            (root / "reference" / "solodit_ingest_cursor_rust.json").write_text(
                json.dumps({"updated_at": "2026-05-20T00:00:00+00:00", "last_id": 200}),
                encoding="utf-8",
            )
            (root / "reference" / "solodit_ingest_cursor_go.json").write_text(
                json.dumps({"updated_at": "2026-05-19T00:00:00+00:00", "last_id": 150}),
                encoding="utf-8",
            )
            tags = root / "audit" / "corpus_tags" / "tags"
            _write_record(tags / "solodit_rust_backfill_20260520" / "case-a")
            go_dir = tags / "solodit_go_backfill_20260520"
            go_dir.mkdir(parents=True)
            (go_dir / "solodit-finding-1.yaml").write_text("schema_version: auditooor.hackerman_record.v1.1\n", encoding="utf-8")

            payload = tool.build_dashboard(
                root=root,
                external_sources_path=registry,
                corpus_mined_path=root / "reference" / "corpus_mined",
                tags_dir=tags,
                agent_reports=[],
                now=NOW,
            )

        row = {row["source_id"]: row for row in payload["rows"]}["solodit_high_plus_findings"]
        self.assertEqual(row["status"], "fresh")
        self.assertEqual(row["cursor_value"], 200)
        self.assertEqual(row["mined_record_count"], 2)
        self.assertEqual(len(row["output_paths"]), 2)

    def test_defimon_row_counts_local_remine_artifacts_when_queued(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "external_intel_sources.yaml"
            registry.parent.mkdir(parents=True)
            registry.write_text(
                """
sources:
  - source_id: defimon_delta_blocked_no_live_source
    name: Defimon delta mining blocked source row
    source_refs:
      - docs/CORPUS_MINING_AND_CASE_STUDY_LOGIC_EXTRACTION_PLAN_2026-05-08.md
      - tools/corpus-mining-state-snapshot.py
    miner:
      tool_path: tools/external-intel-refresh.py
      mode: blocked_no_live_source
    cursor:
      path: .auditooor/external_intel_cursors/defimon.json
      field: status
    ttl: 7d
    output_subtree: audit/corpus_tags/tags/defimon_delta
    status: BLOCKED_NO_LIVE_SOURCE
    backlog_reason: Prior Defimon records exist, but live source/API is not codified.
""".lstrip(),
                encoding="utf-8",
            )
            tool_file = root / "tools" / "external-intel-refresh.py"
            tool_file.parent.mkdir(parents=True)
            tool_file.write_text("# external intel planner\n", encoding="utf-8")
            remine = root / "reference" / "patterns.dsl.r97_defimon_remine_iter2"
            remine.mkdir(parents=True)
            (remine / "defimon-remine.yaml").write_text("id: defimon-remine\n", encoding="utf-8")

            payload = tool.build_dashboard(
                root=root,
                external_sources_path=registry,
                corpus_mined_path=root / "reference" / "corpus_mined",
                tags_dir=root / "audit" / "corpus_tags" / "tags",
                agent_reports=[],
                now=NOW,
            )

        row = {row["source_id"]: row for row in payload["rows"]}["defimon_delta_blocked_no_live_source"]
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["local_pattern_file_count"], 1)
        self.assertEqual(row["mined_file_count"], 1)
        self.assertIn("tools/corpus-mining-state-snapshot.py", row["source_refs"])

    def test_explicit_backlog_source_obligations_propagate_without_queueing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "external_intel_sources.yaml"
            registry.parent.mkdir(parents=True)
            registry.write_text(
                """
sources:
  - source_id: verus_bridge_incident_2026_05
    name: Verus-Ethereum bridge incident backlog item
    url_or_api:
      - https://www.halborn.com/blog/post/explained-the-verus-ethereum-bridge-hack-may-2026
    source_refs:
      - https://www.halborn.com/blog/post/explained-the-verus-ethereum-bridge-hack-may-2026
    source_obligations:
      - obligation_id: verus-root-cause-mechanics
        status: open
        obligation_type: root_cause_validation
        required_evidence: Source-backed root cause and exploit mechanics.
        source_refs:
          - https://www.halborn.com/blog/post/explained-the-verus-ethereum-bridge-hack-may-2026
    miner:
      tool_path: tools/external-intel-refresh.py
      mode: single_incident_backlog
    cursor:
      path: .auditooor/external_intel_cursors/verus_bridge_2026_05.json
      field: incident_status
    ttl: 12h
    output_subtree: audit/corpus_tags/tags/bridge_incidents/verus_bridge_2026_05
    status: backlog
    backlog_reason: Await stable incident mechanics before detector/source-code promotion.
""".lstrip(),
                encoding="utf-8",
            )
            tool_file = root / "tools" / "external-intel-refresh.py"
            tool_file.parent.mkdir(parents=True)
            tool_file.write_text("# external intel planner\n", encoding="utf-8")

            payload = tool.build_dashboard(
                root=root,
                external_sources_path=registry,
                corpus_mined_path=root / "reference" / "corpus_mined",
                tags_dir=root / "audit" / "corpus_tags" / "tags",
                agent_reports=[],
                now=NOW,
            )

        row = {row["source_id"]: row for row in payload["rows"]}["verus_bridge_incident_2026_05"]
        self.assertEqual(row["status"], "backlog")
        self.assertEqual(row["source_obligation_count"], 1)
        self.assertEqual(row["source_obligations"][0]["status"], "open")
        self.assertNotIn("source_refs", row)
        self.assertEqual(payload["summary"]["backlog"], 1)
        self.assertEqual(payload["summary"]["queued"], 0)

    def test_markdown_renders_required_sections(self) -> None:
        payload = {
            "generated_at": "2026-05-20T00:00:00+00:00",
            "summary": {"total_sources": 1, "fresh": 0, "queued": 0, "stale": 0, "missing": 1, "backlog": 0},
            "rows": [
                {
                    "source_id": "solodit_high_plus_findings",
                    "source_kind": "external_intel_registry",
                    "status": "missing",
                    "last_mined_at": None,
                    "mined_record_count": 0,
                    "mined_file_count": 0,
                    "reason": "no local cursor or mined output found",
                }
            ],
            "stale_rows": [],
            "missing_rows": [{"source_id": "solodit_high_plus_findings", "reason": "no local cursor"}],
            "backlog_rows": [],
            "queued_rows": [],
        }
        md = tool.render_markdown(payload)
        self.assertTrue(md.startswith("# Mining Coverage Dashboard"))
        self.assertIn("## Stale Rows", md)
        self.assertIn("## Missing Rows", md)
        self.assertIn("## Backlog Rows", md)
        self.assertIn("## Queued Rows", md)
        self.assertIn("solodit_high_plus_findings", md)

    def test_cli_writes_json_and_markdown_from_temp_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = _write_registry(root)
            out_json = root / "out" / "coverage.json"
            out_md = root / "out" / "coverage.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--root",
                    str(root),
                    "--external-sources",
                    str(registry),
                    "--corpus-mined",
                    str(root / "reference" / "corpus_mined"),
                    "--tags-dir",
                    str(root / "audit" / "corpus_tags" / "tags"),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--quiet",
                ],
                cwd=str(REPO_ROOT),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            md = out_md.read_text(encoding="utf-8")

        self.assertEqual(payload["schema"], tool.SCHEMA_VERSION)
        self.assertIn("Mining Coverage Dashboard", md)
        self.assertIn("defillama_hacks_tvl", md)


if __name__ == "__main__":
    unittest.main()
