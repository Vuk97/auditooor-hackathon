"""Tests for tools/hackerman-etl-from-bridge-incidents.py.

These guard the Wave-1 bridge-incidents miner against M14-trap drift
(invented incident IDs, missing URLs, schema regressions, slug churn).
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-bridge-incidents.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


_URL_RE = re.compile(r"^https?://[^\s]+$")


class HackermanEtlFromBridgeIncidentsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_bridge_incidents")
        self.validator = _load(
            VALIDATOR, "_hackerman_record_validate_for_bridge_incidents"
        )

    # 1. Dry-run completes with zero schema errors and a non-zero record count.
    def test_dry_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-incidents-dry-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertEqual(summary["errors"], [])
        self.assertGreaterEqual(summary["records_emitted"], 20)
        self.assertEqual(summary["verification_tier"], "tier-2-verified-public-archive")

    # 2. Every curated incident has at least one resolvable URL ref.
    def test_every_incident_has_real_url_reference(self) -> None:
        for incident in self.tool.INCIDENTS:
            refs = incident.get("refs") or []
            self.assertTrue(refs, f"incident {incident['slug']} has no refs")
            for url in refs:
                self.assertTrue(
                    _URL_RE.match(url),
                    f"incident {incident['slug']} ref not a URL: {url!r}",
                )

    # 3. Slug normalization: every slug round-trips through slugify unchanged.
    def test_slug_normalization_is_stable(self) -> None:
        for incident in self.tool.INCIDENTS:
            slug = incident["slug"]
            self.assertEqual(
                slug,
                self.tool.slugify(slug, max_len=110),
                f"slug not normalized: {slug!r}",
            )

    # 4. source_audit_ref is a real URL (the first ref).
    def test_source_audit_ref_is_url(self) -> None:
        for incident in self.tool.INCIDENTS:
            record = self.tool.incident_to_record(incident)
            self.assertTrue(
                _URL_RE.match(record["source_audit_ref"]),
                f"source_audit_ref not a URL: {record['source_audit_ref']!r}",
            )

    # 5. record_id is unique across all incidents.
    def test_record_id_uniqueness(self) -> None:
        ids = [self.tool.incident_to_record(i)["record_id"] for i in self.tool.INCIDENTS]
        self.assertEqual(len(ids), len(set(ids)), "duplicate record_ids in INCIDENTS")

    # 6. Records validate against the live schema.
    def test_records_validate_against_schema(self) -> None:
        for incident in self.tool.INCIDENTS:
            record = self.tool.incident_to_record(incident)
            errs = self.validator.validate_doc(record)
            self.assertEqual(
                errs, [], f"schema errors for {incident['slug']}: {errs}"
            )

    # 7. impact_dollar_class respects the bucket boundaries.
    def test_impact_dollar_class_buckets(self) -> None:
        cases = [
            (1_500_000_000, ">=$1M"),
            (100_000_000, ">=$1M"),
            (1_000_000, ">=$1M"),
            (999_999, "$100K-$1M"),
            (50_000, "$10K-$100K"),
            (5_000, "<$10K"),
            (0, "non-financial"),
        ]
        for usd, expected in cases:
            self.assertEqual(
                self.tool._dollar_class(usd),
                expected,
                f"bucket mismatch for {usd}",
            )

    # 8. Records contain a verification_tier= line in required_preconditions.
    def test_verification_tier_marker_present(self) -> None:
        for incident in self.tool.INCIDENTS:
            record = self.tool.incident_to_record(incident)
            tier_lines = [
                p
                for p in record["required_preconditions"]
                if p.startswith("verification_tier=")
            ]
            self.assertEqual(
                len(tier_lines), 1, f"missing/duplicate verification_tier in {incident['slug']}"
            )
            self.assertEqual(
                tier_lines[0],
                "verification_tier=tier-2-verified-public-archive",
            )

    # 9. Real-emit writes record.json + record.yaml per slug.
    def test_real_emit_writes_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bridge-incidents-emit-") as tmp:
            out = Path(tmp) / "out"
            summary = self.tool.convert(out, dry_run=False, limit=3)
            self.assertEqual(summary["records_emitted"], 3)
            emitted_files = list(out.rglob("record.json"))
            self.assertEqual(len(emitted_files), 3)
            for jf in emitted_files:
                yf = jf.with_suffix(".yaml")
                self.assertTrue(yf.exists(), f"missing yaml sibling for {jf}")
                data = json.loads(jf.read_text(encoding="utf-8"))
                self.assertEqual(data["schema_version"], "auditooor.hackerman_record.v1.1")
                self.assertEqual(data["verification_tier"], "tier-2-verified-public-archive")
                self.assertTrue(_URL_RE.match(data["record_source_url"]))

    # 10. target_domain is always 'bridge' (this miner is bridge-only).
    def test_target_domain_is_bridge(self) -> None:
        for incident in self.tool.INCIDENTS:
            record = self.tool.incident_to_record(incident)
            self.assertEqual(record["target_domain"], "bridge")

    # 11. Year matches incident date prefix.
    def test_year_matches_date(self) -> None:
        for incident in self.tool.INCIDENTS:
            record = self.tool.incident_to_record(incident)
            self.assertEqual(
                record["year"], int(incident["date"][:4]),
                f"year mismatch for {incident['slug']}",
            )

    # 12. At least one well-known canonical incident is present (Ronin, Wormhole, Nomad).
    def test_canonical_incidents_present(self) -> None:
        slugs = {i["slug"] for i in self.tool.INCIDENTS}
        for required in {"ronin-network-2022-03", "wormhole-2022-02", "nomad-bridge-2022-08"}:
            self.assertIn(required, slugs)


if __name__ == "__main__":
    unittest.main()
