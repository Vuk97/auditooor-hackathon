"""Tests for tools/external-intel-refresh.py."""
from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "tools" / "external-intel-refresh.py"
REGISTRY = REPO / "reference" / "external_intel_sources.yaml"
MAKEFILE = REPO / "Makefile"


def load_runner():
    spec = importlib.util.spec_from_file_location("external_intel_refresh", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ExternalIntelRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load_runner()

    def setUp(self):
        self.data = self.runner.load_registry(REGISTRY)

    def test_registry_validates_cleanly(self):
        errors = self.runner.validate_registry(self.data, repo_root=REPO)
        self.assertEqual(errors, [])

    def test_source_selection_rejects_unknown_ids(self):
        with self.assertRaises(self.runner.RegistryError):
            self.runner.select_sources(self.data, ["not_a_registered_source"])

    def test_defillama_and_rekt_plan_existing_postmortem_miner_without_fetch(self):
        rows = {
            row["source_id"]: row
            for row in self.runner.select_sources(
                self.data, ["defillama_hacks_tvl", "rekt_news_incidents"]
            )
        }

        defillama = self.runner.plan_source(rows["defillama_hacks_tvl"], date="2026-05-20", repo_root=REPO)
        rekt = self.runner.plan_source(rows["rekt_news_incidents"], date="2026-05-20", repo_root=REPO)

        self.assertEqual(defillama["status"], "planned")
        self.assertEqual(rekt["status"], "planned")
        self.assertIn("tools/hackerman-etl-from-post-mortem.py", defillama["command"])
        self.assertIn("defillama", defillama["command"])
        self.assertIn("rekt", rekt["command"])
        self.assertIn("--dry-run", defillama["command"])
        self.assertIn("--json-summary", rekt["command"])
        self.assertNotIn("--fetch", defillama["command"])
        self.assertNotIn("--fetch", rekt["command"])

    def test_postmortem_sources_can_emit_bounded_live_fetch_plan(self):
        rows = {
            row["source_id"]: row
            for row in self.runner.select_sources(
                self.data, ["defillama_hacks_tvl", "rekt_news_incidents", "darknavy_web3_pages"]
            )
        }

        defillama = self.runner.plan_source(
            rows["defillama_hacks_tvl"],
            date="2026-05-20",
            repo_root=REPO,
            allow_live_fetch=True,
            max_pages=3,
        )
        rekt = self.runner.plan_source(
            rows["rekt_news_incidents"],
            date="2026-05-20",
            repo_root=REPO,
            allow_live_fetch=True,
            max_pages=3,
        )
        darknavy = self.runner.plan_source(
            rows["darknavy_web3_pages"],
            date="2026-05-20",
            repo_root=REPO,
            allow_live_fetch=True,
            max_pages=3,
        )

        self.assertEqual(defillama["status"], "live_planned")
        self.assertEqual(rekt["status"], "live_planned")
        self.assertEqual(darknavy["status"], "live_planned")
        self.assertIn("--fetch", defillama["command"])
        self.assertIn("--max-pages", defillama["command"])
        self.assertIn("3", defillama["command"])
        self.assertNotIn("--dry-run", rekt["command"])
        self.assertEqual(defillama["activation_gate"], "explicit_operator_flag")
        self.assertIn("--fetch", darknavy["command"])
        self.assertIn("--max-pages", darknavy["command"])

    def test_defimon_delegates_to_freshness_check_and_darknavy_has_offline_plan(self):
        rows = {
            row["source_id"]: row
            for row in self.runner.select_sources(
                self.data,
                [
                    "defimon_delta_blocked_no_live_source",
                    "verus_bridge_incident_2026_05",
                    "darknavy_web3_pages",
                ],
            )
        }

        defimon = self.runner.plan_source(
            rows["defimon_delta_blocked_no_live_source"], date="2026-05-20", repo_root=REPO
        )
        verus = self.runner.plan_source(
            rows["verus_bridge_incident_2026_05"], date="2026-05-20", repo_root=REPO
        )
        darknavy = self.runner.plan_source(rows["darknavy_web3_pages"], date="2026-05-20", repo_root=REPO)

        self.assertEqual(defimon["status"], "delegated_plan")
        self.assertEqual(defimon["plan_kind"], "make_target")
        self.assertEqual(defimon["command"], ["make", "defimon-staleness-check", "JSON=1"])
        self.assertEqual(
            defimon["operator_authorized_source_closure"]["blocker_id"],
            "BLK-V3-SOURCE-DEFIMON-NO-LIVE-SOURCE",
        )
        self.assertIn(
            "https://t.me/s/defimon_alerts",
            defimon["operator_authorized_source_closure"]["source_refs"],
        )
        self.assertEqual(verus["status"], "backlog")
        self.assertGreaterEqual(len(verus["source_obligations"]), 3)
        verus_obligation_status = {
            item["obligation_id"]: item["status"] for item in verus["source_obligations"]
        }
        self.assertEqual(verus_obligation_status["verus-incident-date-and-loss"], "closed")
        self.assertEqual(verus_obligation_status["verus-root-cause-mechanics"], "closed")
        self.assertEqual(verus_obligation_status["verus-contract-path-anchors"], "closed")
        self.assertEqual(darknavy["status"], "planned")
        self.assertEqual(darknavy["plan_kind"], "command")
        self.assertIn("tools/hackerman-etl-from-darknavy-web3.py", darknavy["command"])
        self.assertIn("audit/corpus_tags/tags/darknavy_web3_incidents", darknavy["command"])
        self.assertNotIn("--fetch", darknavy["command"])
        self.assertIn("--dry-run", darknavy["command"])

    def test_bridge_backlog_source_obligations_propagate_without_completion(self):
        rows = {
            row["source_id"]: row
            for row in self.runner.select_sources(
                self.data,
                ["verus_bridge_incident_2026_05", "map_butter_bridge_incident_2026_05"],
            )
        }

        verus = self.runner.plan_source(
            rows["verus_bridge_incident_2026_05"], date="2026-05-20", repo_root=REPO
        )
        map_butter = self.runner.plan_source(
            rows["map_butter_bridge_incident_2026_05"], date="2026-05-20", repo_root=REPO
        )

        self.assertEqual(verus["status"], "backlog")
        self.assertEqual(map_butter["status"], "operator_authorized_source_closure")
        self.assertEqual(verus["plan_kind"], "source_collection")
        self.assertEqual(map_butter["plan_kind"], "source_collection")
        self.assertFalse(verus["source_collection"]["promotion_allowed"])
        self.assertFalse(map_butter["source_collection"]["promotion_allowed"])
        self.assertEqual(
            map_butter["operator_authorized_source_closure"]["blocker_id"],
            "BLK-V3-SOURCE-RECENT-BRIDGE-OPEN-OBLIGATIONS",
        )
        self.assertIn(
            "operator_authorized_source_closure_is_not_external_platform_outcome_evidence",
            map_butter["source_collection"]["promotion_blockers"],
        )
        self.assertIn(
            "https://www.halborn.com/blog/post/explained-the-verus-ethereum-bridge-hack-may-2026",
            verus["source_collection"]["source_urls"],
        )
        self.assertIn(
            "https://github.com/DarkNavySecurity/web3-exploit-analysis/tree/main/artifacts/"
            "analysis_0x6990f01720f57fc515d0e976a0c4f8157e0a9529194c4c15d190e98d087eb321",
            verus["source_collection"]["source_urls"],
        )
        self.assertIn(
            "audit/corpus_tags/tags/bridge_incidents/verus_bridge_2026_05/record.yaml",
            verus["source_collection"]["local_refs"],
        )
        self.assertNotIn("command", verus)
        self.assertIn("verus-root-cause-mechanics", {item["obligation_id"] for item in verus["source_obligations"]})
        self.assertIn(
            "map-butter-message-binding-root-cause",
            {item["obligation_id"] for item in map_butter["source_obligations"]},
        )
        map_obligation_status = {
            item["obligation_id"]: item["status"] for item in map_butter["source_obligations"]
        }
        self.assertEqual(map_obligation_status["map-butter-primary-response-source"], "closed")
        self.assertEqual(map_obligation_status["map-butter-selector-and-call-path"], "operator_authorized_closed")
        self.assertEqual(map_obligation_status["map-butter-message-binding-root-cause"], "operator_authorized_closed")
        self.assertEqual(map_obligation_status["map-butter-companion-chain-flow"], "closed")
        self.assertEqual(map_butter["source_collection"]["open_source_obligation_ids"], [])
        self.assertEqual(
            set(map_butter["source_collection"]["nonblocking_former_source_obligation_ids"]),
            {"map-butter-selector-and-call-path", "map-butter-message-binding-root-cause"},
        )

    def test_single_incident_backlog_ignores_allow_live_fetch(self):
        row = self.runner.select_sources(self.data, ["verus_bridge_incident_2026_05"])[0]
        plan = self.runner.plan_source(
            row,
            date="2026-05-20",
            repo_root=REPO,
            allow_live_fetch=True,
            max_pages=3,
        )

        self.assertEqual(plan["status"], "backlog")
        self.assertEqual(plan["plan_kind"], "source_collection")
        self.assertFalse(plan["live_fetch_enabled"])
        self.assertNotIn("command", plan)
        self.assertNotIn("fetched_sources", plan["source_collection"])

    def test_single_incident_fetch_fixture_mode_requires_explicit_flag_and_blocks_promotion(self):
        row = self.runner.select_sources(self.data, ["verus_bridge_incident_2026_05"])[0]
        first_url = row["url_or_api"][0]
        with tempfile.TemporaryDirectory() as td:
            fixture_dir = Path(td) / "fixtures"
            fixture_dir.mkdir()
            cache_dir = Path(td) / "cache"
            fixture_body = b"verus fixture body"
            (fixture_dir / f"{self.runner._url_cache_key(first_url)}.body").write_bytes(fixture_body)

            no_fetch = self.runner.plan_source(
                row,
                date="2026-05-20",
                repo_root=REPO,
                fixture_dir=fixture_dir,
            )
            fetched = self.runner.plan_source(
                row,
                date="2026-05-20",
                repo_root=REPO,
                fetch_single_incident=True,
                fixture_dir=fixture_dir,
                cache_dir=cache_dir,
            )

        self.assertEqual(no_fetch["status"], "backlog")
        self.assertNotIn("fetched_sources", no_fetch["source_collection"])
        self.assertEqual(fetched["status"], "backlog")
        self.assertTrue(fetched["single_incident_fetch_enabled"])
        self.assertFalse(fetched["live_fetch_enabled"])
        collection = fetched["source_collection"]
        self.assertEqual(collection["schema"], self.runner.SINGLE_INCIDENT_FETCH_SCHEMA)
        self.assertFalse(collection["promotion_allowed"])
        self.assertNotIn("open_source_obligations", collection["promotion_blockers"])
        self.assertIn("manual_promotion_review_required", collection["promotion_blockers"])
        self.assertNotIn("verus-root-cause-mechanics", collection["open_source_obligation_ids"])
        self.assertEqual(collection["fetch_status_counts"].get("fixture"), 1)
        fixture_rows = [item for item in collection["fetched_sources"] if item["status"] == "fixture"]
        self.assertEqual(len(fixture_rows), 1)
        self.assertEqual(fixture_rows[0]["sha256"], hashlib.sha256(fixture_body).hexdigest())

    def test_operator_authorized_single_incident_fetch_live_requires_both_flags(self):
        row = self.runner.select_sources(self.data, ["map_butter_bridge_incident_2026_05"])[0]

        allow_live_only = self.runner.plan_source(
            row,
            date="2026-05-20",
            repo_root=REPO,
            allow_live_fetch=True,
        )
        with tempfile.TemporaryDirectory() as td:
            explicit_no_live = self.runner.plan_source(
                row,
                date="2026-05-20",
                repo_root=REPO,
                fetch_single_incident=True,
                allow_live_fetch=False,
                cache_dir=Path(td) / "cache",
            )

        self.assertEqual(allow_live_only["status"], "operator_authorized_source_closure")
        self.assertNotIn("fetched_sources", allow_live_only["source_collection"])
        self.assertFalse(allow_live_only["single_incident_fetch_enabled"])
        self.assertTrue(explicit_no_live["single_incident_fetch_enabled"])
        self.assertFalse(explicit_no_live["live_fetch_enabled"])
        self.assertIn("not_fetched", explicit_no_live["source_collection"]["fetch_status_counts"])
        self.assertEqual(explicit_no_live["source_collection"]["open_source_obligation_ids"], [])
        self.assertIn(
            "map-butter-selector-and-call-path",
            explicit_no_live["source_collection"]["nonblocking_former_source_obligation_ids"],
        )

    def test_summary_counts_single_incident_collection_rows_as_backlog(self):
        selected = self.runner.select_sources(
            self.data,
            ["verus_bridge_incident_2026_05", "map_butter_bridge_incident_2026_05"],
        )
        summary = self.runner.build_summary(
            self.data,
            selected=selected,
            validation_errors=[],
            date="2026-05-20",
            registry_path=REGISTRY,
            repo_root=REPO,
        )

        self.assertEqual(summary["counts"], {"backlog": 1, "operator_authorized_source_closure": 1})
        self.assertTrue(all(plan["plan_kind"] == "source_collection" for plan in summary["plans"]))

    def test_summary_counts_single_incident_fetch_rows_as_backlog(self):
        selected = self.runner.select_sources(
            self.data,
            ["verus_bridge_incident_2026_05", "map_butter_bridge_incident_2026_05"],
        )
        summary = self.runner.build_summary(
            self.data,
            selected=selected,
            validation_errors=[],
            date="2026-05-20",
            registry_path=REGISTRY,
            repo_root=REPO,
            fetch_single_incident=True,
        )

        self.assertEqual(summary["counts"], {"backlog": 1, "operator_authorized_source_closure": 1})
        self.assertTrue(summary["fetch_single_incident"])
        self.assertTrue(
            all(plan["source_collection"]["schema"] == self.runner.SINGLE_INCIDENT_FETCH_SCHEMA for plan in summary["plans"])
        )

    def test_summary_counts_selected_statuses(self):
        selected = self.runner.select_sources(
            self.data,
            ["defillama_hacks_tvl", "rekt_news_incidents", "defimon_delta_blocked_no_live_source"],
        )
        summary = self.runner.build_summary(
            self.data,
            selected=selected,
            validation_errors=[],
            date="2026-05-20",
            registry_path=REGISTRY,
            repo_root=REPO,
        )
        self.assertEqual(summary["schema"], "auditooor.external_intel_refresh.summary.v1")
        self.assertTrue(summary["registry_valid"])
        self.assertEqual(summary["counts"], {"planned": 2, "delegated_plan": 1})
        self.assertEqual(
            summary["selected_source_ids"],
            ["defillama_hacks_tvl", "rekt_news_incidents", "defimon_delta_blocked_no_live_source"],
        )

    def test_summary_counts_live_planned_sources_separately(self):
        selected = self.runner.select_sources(self.data, ["defillama_hacks_tvl", "rekt_news_incidents"])
        summary = self.runner.build_summary(
            self.data,
            selected=selected,
            validation_errors=[],
            date="2026-05-20",
            registry_path=REGISTRY,
            repo_root=REPO,
            allow_live_fetch=True,
            max_pages=2,
        )

        self.assertEqual(summary["counts"], {"live_planned": 2})
        self.assertTrue(summary["allow_live_fetch"])
        self.assertEqual(summary["activation_gate"], "explicit_operator_flag")
        self.assertEqual(summary["max_pages"], 2)

    def test_cli_json_summary_and_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "summary.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--source",
                    "rekt_news_incidents",
                    "--date",
                    "2026-05-20",
                    "--json-summary",
                    "--output",
                    str(out),
                ],
                cwd=REPO,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            written = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["selected_source_ids"], ["rekt_news_incidents"])
            self.assertEqual(payload["plans"][0]["status"], "planned")
            self.assertEqual(written["plans"][0]["command"], payload["plans"][0]["command"])

    def test_makefile_targets_expose_runner_and_tests(self):
        makefile = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("external-intel-refresh:", makefile)
        self.assertIn("external-intel-refresh-test:", makefile)
        self.assertIn("tools/external-intel-refresh.py", makefile)
        self.assertIn("--allow-live-fetch", makefile)
        self.assertIn("--fetch-single-incident", makefile)
        self.assertIn("--cache-dir", makefile)
        self.assertIn("--fixture-dir", makefile)
        self.assertIn("--max-pages", makefile)
        self.assertIn("--timeout-seconds", makefile)
        self.assertIn("tools.tests.test_external_intel_refresh", makefile)
        phony_lines = [
            line for line in makefile.splitlines()
            if line.startswith(".PHONY:") and "external-intel-refresh" in line
        ]
        self.assertTrue(phony_lines, ".PHONY line for external-intel-refresh missing")


if __name__ == "__main__":
    unittest.main()
