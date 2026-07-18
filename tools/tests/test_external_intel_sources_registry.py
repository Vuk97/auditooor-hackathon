"""Offline checks for reference/external_intel_sources.yaml."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "reference" / "external_intel_sources.yaml"


class ExternalIntelSourcesRegistryTests(unittest.TestCase):
    def setUp(self):
        self.data = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
        self.sources = self.data["sources"]

    def test_schema_and_unique_source_ids(self):
        self.assertEqual(self.data["schema"], "auditooor.external_intel_sources.v1")
        ids = [row["source_id"] for row in self.sources]
        self.assertEqual(len(ids), len(set(ids)))

    def test_registry_is_json_serializable_after_yaml_load(self):
        json.dumps(self.data)

    def test_i1_required_shape_present_for_every_source(self):
        required = {
            "source_id",
            "url_or_api",
            "miner",
            "cursor",
            "ttl",
            "output_subtree",
            "quality_gate",
            "network_requirement",
            "promotion_target",
        }
        ttl_re = re.compile(r"^\d+[hdw]$")
        for row in self.sources:
            with self.subTest(source_id=row.get("source_id")):
                self.assertTrue(required.issubset(row))
                self.assertRegex(row["ttl"], ttl_re)
                self.assertIn("tool_path", row["miner"])
                self.assertIn("type", row["cursor"])
                self.assertIn("required_fields", row["quality_gate"])
                self.assertIn("required", row["network_requirement"])
                self.assertIn("corpus_subtree", row["promotion_target"])
                self.assertTrue(row.get("source_refs"))

    def test_required_source_families_are_represented(self):
        ids = " ".join(row["source_id"] for row in self.sources)
        for marker in ("solodit", "defimon", "darknavy", "pashov", "sb_security", "verus"):
            with self.subTest(marker=marker):
                self.assertIn(marker, ids)

    def test_defimon_has_public_source_refresh_after_blog_mine(self):
        rows = [row for row in self.sources if "defimon" in row["source_id"]]
        self.assertEqual(len(rows), 1)
        self.assertNotEqual(rows[0].get("status"), "BLOCKED_NO_LIVE_SOURCE")
        self.assertIn("https://defimon.xyz/blog", rows[0].get("url_or_api", []))
        self.assertEqual(rows[0]["miner"].get("mode"), "public_telegram_and_blog_refresh")

    def test_darknavy_requires_planned_case_study_fields(self):
        row = next(row for row in self.sources if row["source_id"] == "darknavy_web3_pages")
        required_fields = set(row["quality_gate"]["required_fields"])
        self.assertTrue({"impact", "source_anchors", "detector_hypotheses"}.issubset(required_fields))

    def test_sb_security_public_audits_are_tracked_like_audit_firm_findings(self):
        row = next(row for row in self.sources if row["source_id"] == "sb_security_public_audits")
        self.assertEqual(row["miner"]["tool_path"], "tools/hackerman-etl-from-audit-firm-pdf-sb-security.py")
        self.assertEqual(row["miner"]["makefile_target"], "hackerman-etl-from-audit-firm-pdf-sb-security")
        self.assertEqual(row["output_subtree"], "audit/corpus_tags/tags/audit_firm_findings_sb_security")
        self.assertIn("reports/sb_security_pdf_mine_20260521.json", row["source_refs"])
        self.assertIn("record_source_url", row["quality_gate"]["required_fields"])
        self.assertIn("record_extensions.title", row["quality_gate"]["required_fields"])

    def test_bridge_backlog_items_keep_open_source_obligations(self):
        rows = {
            row["source_id"]: row
            for row in self.sources
            if row["source_id"] in {"verus_bridge_incident_2026_05", "map_butter_bridge_incident_2026_05"}
        }
        self.assertEqual(set(rows), {"verus_bridge_incident_2026_05", "map_butter_bridge_incident_2026_05"})
        for source_id, row in rows.items():
            with self.subTest(source_id=source_id):
                self.assertEqual(row.get("status"), "backlog")
                self.assertEqual(row["miner"].get("mode"), "single_incident_fetch")
                self.assertEqual(row["fetch_adapter"].get("adapter"), "single_incident_url_set")
                self.assertIn("output_artifact", row["fetch_adapter"])
                self.assertIn("primary_or_security_firm", row["fetch_adapter"].get("required_url_roles", []))
                obligations = row.get("source_obligations")
                self.assertIsInstance(obligations, list)
                self.assertGreaterEqual(len(obligations), 3)
                for obligation in obligations:
                    if (
                        source_id == "verus_bridge_incident_2026_05"
                        and obligation.get("obligation_id")
                        in {"verus-incident-date-and-loss", "verus-contract-path-anchors"}
                    ) or (
                        source_id == "map_butter_bridge_incident_2026_05"
                        and obligation.get("obligation_id")
                        in {"map-butter-primary-response-source", "map-butter-companion-chain-flow"}
                    ):
                        self.assertEqual(obligation.get("status"), "closed")
                        self.assertIsInstance(obligation.get("closure_evidence"), dict)
                        self.assertTrue(obligation["closure_evidence"])
                    else:
                        self.assertEqual(obligation.get("status"), "open")
                    self.assertIsInstance(obligation.get("source_refs"), list)
                    for key in ("obligation_id", "obligation_type", "required_evidence"):
                        self.assertIsInstance(obligation.get(key), str)
                        self.assertTrue(obligation[key].strip())

        verus_refs = "\n".join(rows["verus_bridge_incident_2026_05"].get("source_refs", []))
        self.assertIn("DarkNavySecurity/web3-exploit-analysis", verus_refs)


if __name__ == "__main__":
    unittest.main()
