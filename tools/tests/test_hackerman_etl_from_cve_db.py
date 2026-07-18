"""Tests for tools/hackerman-etl-from-cve-db.py."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-cve-db.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromCveDbTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_cve_db")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_cve_db")

    def test_seed_emits_two_records_per_entry(self) -> None:
        records = self.tool.build_all_records()
        # Each seed entry expands to 2 mitigation states.
        self.assertEqual(len(records), 2 * len(self.tool.SEED_CVES))
        self.assertGreaterEqual(len(records), 18, f"expected >=18 records, got {len(records)}")

    def test_every_seed_entry_has_reference_url(self) -> None:
        for entry in self.tool.SEED_CVES:
            urls = entry.get("reference_urls") or []
            self.assertTrue(
                urls,
                f"seed entry {entry.get('cve_id') or entry.get('ghsa_id')!r} missing reference_urls",
            )
            for url in urls:
                self.assertTrue(
                    url.startswith("http://") or url.startswith("https://"),
                    f"reference_url {url!r} does not look like a URL",
                )

    def test_every_seed_entry_has_advisory_id(self) -> None:
        for entry in self.tool.SEED_CVES:
            cve = (entry.get("cve_id") or "").strip().lower()
            ghsa = (entry.get("ghsa_id") or "").strip().lower()
            # At least one must be non-"n/a".
            self.assertTrue(
                cve not in {"", "n/a"} or ghsa not in {"", "n/a"},
                f"seed entry {entry.get('title')!r} has neither cve_id nor ghsa_id",
            )

    def test_every_seed_entry_has_explicit_fixed_versions_field(self) -> None:
        for entry in self.tool.SEED_CVES:
            self.assertIn("fixed_versions", entry, f"seed entry {entry.get('title')!r} missing fixed_versions field")
            # Field must be a non-empty string (may be 'deployment-bound' / 'unfixed' / 'ack-no-fix' / a version).
            self.assertIsInstance(entry["fixed_versions"], str)
            self.assertTrue(entry["fixed_versions"].strip(), f"seed entry {entry.get('title')!r} has blank fixed_versions")

    def test_pre_fix_and_post_fix_states_both_present(self) -> None:
        records = self.tool.build_all_records()
        states_seen = set()
        for record in records:
            for state in ("pre-fix", "post-fix-released"):
                if f":{state}" in record["source_audit_ref"]:
                    states_seen.add(state)
                    break
        self.assertEqual(states_seen, {"pre-fix", "post-fix-released"})

    def test_pre_fix_severity_preserved_post_fix_walked_back(self) -> None:
        records = self.tool.build_all_records()
        by_ref: dict = {}
        for record in records:
            by_ref[record["source_audit_ref"]] = record
        walk_back = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}
        unfixed_tokens = {"unfixed", "ack-no-fix", "deployment-bound", "n/a", ""}
        def _advisory_for(entry):
            cve = (entry.get("cve_id") or "").strip()
            if cve and cve.lower() != "n/a":
                return cve
            return (entry.get("ghsa_id") or "").strip()

        for entry in self.tool.SEED_CVES:
            advisory = _advisory_for(entry)
            slug = self.tool.slugify(advisory, max_len=60)
            pre_ref = f"cve-db:{slug}:pre-fix"
            post_ref = f"cve-db:{slug}:post-fix-released"
            pre = by_ref.get(pre_ref)
            post = by_ref.get(post_ref)
            self.assertIsNotNone(pre, f"missing pre-fix record for {advisory}")
            self.assertIsNotNone(post, f"missing post-fix record for {advisory}")
            expected_pre = entry.get("severity", "medium").lower()
            self.assertEqual(pre["severity_at_finding"], expected_pre, advisory)
            fixed = str(entry.get("fixed_versions") or "").strip().lower()
            if fixed in unfixed_tokens:
                # Unfixed / deployment-bound: severity preserved.
                self.assertEqual(post["severity_at_finding"], expected_pre, advisory)
            else:
                self.assertEqual(post["severity_at_finding"], walk_back[expected_pre], advisory)

    def test_records_validate_against_v1_schema(self) -> None:
        records = self.tool.build_all_records()
        errors = self.tool.validate_records(records)
        self.assertEqual(errors, [], f"schema validation errors: {errors[:5]}")

    def test_record_ids_unique_and_pattern_safe(self) -> None:
        records = self.tool.build_all_records()
        ids = [record["record_id"] for record in records]
        self.assertEqual(len(ids), len(set(ids)), "record_ids must be unique")
        for rid in ids:
            self.assertRegex(rid, r"^[A-Za-z0-9._:/-]{8,160}$")

    def test_related_records_link_pre_and_post_fix_pair(self) -> None:
        records = self.tool.build_all_records()
        by_id = {record["record_id"]: record for record in records}
        for record in records:
            self.assertGreaterEqual(
                len(record["related_records"]),
                1,
                f"{record['record_id']} should link to its sibling state",
            )
            for related in record["related_records"]:
                self.assertIn(related, by_id, f"related {related!r} not in emitted set")

    def test_fixed_versions_recorded_in_preconditions(self) -> None:
        records = self.tool.build_all_records()
        for record in records:
            self.assertTrue(
                any(p.startswith("fixed_versions=") for p in record["required_preconditions"]),
                f"{record['record_id']} missing fixed_versions= precondition",
            )
            self.assertTrue(
                any(p.startswith("affected_versions=") for p in record["required_preconditions"]),
                f"{record['record_id']} missing affected_versions= precondition",
            )
            self.assertTrue(
                any(p.startswith("mitigation_state=") for p in record["required_preconditions"]),
                f"{record['record_id']} missing mitigation_state= precondition",
            )

    def test_no_fabricated_fix_version_when_upstream_unfixed(self) -> None:
        records = self.tool.build_all_records()
        unfixed_tokens = {"unfixed", "ack-no-fix", "deployment-bound", "n/a", ""}
        for entry in self.tool.SEED_CVES:
            fixed = str(entry.get("fixed_versions") or "").strip().lower()
            if fixed not in unfixed_tokens:
                continue
            cve = (entry.get("cve_id") or "").strip()
            advisory = cve if cve and cve.lower() != "n/a" else (entry.get("ghsa_id") or "").strip()
            slug = self.tool.slugify(advisory, max_len=60)
            for record in records:
                if not record["source_audit_ref"].startswith(f"cve-db:{slug}:"):
                    continue
                # The post-fix attacker_action_sequence must not invent
                # a fix-version pointer; it must reference the upstream
                # state ('unfixed' / 'deployment-bound') verbatim.
                action = record["attacker_action_sequence"]
                self.assertNotRegex(
                    action,
                    r"upstream patch shipped in (?!deployment-bound|unfixed|ack-no-fix)\S+",
                    f"{record['record_id']} fabricated a fix-version pointer",
                )

    def test_cli_writes_schema_valid_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(["--out-dir", str(out_dir), "--json-summary"])
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertGreaterEqual(len(files), 18)
            schema = self.validator.load_schema()
            for path in files[:6]:
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", (path, errors))

    def test_cli_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out_dry"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(["--out-dir", str(out_dir), "--dry-run", "--json-summary"])
            self.assertEqual(rc, 0)
            self.assertFalse(out_dir.exists(), "dry-run must not create out_dir")

    def test_cli_limit_caps_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out_limit"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--limit",
                        "4",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            summary = json.loads(buf.getvalue())
            self.assertEqual(summary["records_emitted"], 4)
            self.assertEqual(summary["file_count"], 4)

    def test_extra_json_extends_seed(self) -> None:
        extra_entry = [{
            "cve_id": "CVE-TEST-EXTRA-2026",
            "ghsa_id": "GHSA-test-test-test",
            "year": 2026,
            "title": "Synthetic CVE-DB extra entry for test harness",
            "description": "Synthetic extra entry to verify --extra-json wiring.",
            "attacker_action_sequence": "Synthetic action sequence used in test harness.",
            "fix_pattern": "Apply the synthetic fix pattern.",
            "fix_anti_pattern": "Avoid the synthetic anti-pattern.",
            "attack_class": "test-only-bug-class",
            "bug_class": "test-only-bug-class",
            "severity": "low",
            "impact_class": "griefing",
            "impact_actor": "arbitrary-user",
            "impact_dollar_class": "<$10K",
            "target_domain": "vault",
            "target_language": "solidity",
            "target_repo": "unknown",
            "affected_versions": "<1.0.0",
            "fixed_versions": "1.0.0",
            "preconditions": ["synthetic precondition"],
            "reference_urls": ["https://example.com/test-cve"],
        }]
        baseline = 2 * len(self.tool.SEED_CVES)
        with tempfile.TemporaryDirectory() as tmp:
            extra_path = Path(tmp) / "extra.json"
            extra_path.write_text(json.dumps(extra_entry), encoding="utf-8")
            out_dir = Path(tmp) / "out_extra"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--extra-json",
                        str(extra_path),
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            summary = json.loads(buf.getvalue())
            self.assertEqual(summary["extra_entries"], 1)
            self.assertEqual(summary["records_emitted"], baseline + 2)

    def test_seed_entry_without_reference_urls_raises(self) -> None:
        bad = {
            "cve_id": "CVE-TEST-NOURL-2026",
            "year": 2026,
            "title": "No-URL seed entry",
            "attacker_action_sequence": "x",
            "fix_pattern": "y",
            "fix_anti_pattern": "z",
            "attack_class": "bug",
            "bug_class": "bug",
            "severity": "low",
            "preconditions": ["p"],
            "fixed_versions": "1",
            "reference_urls": [],
        }
        with self.assertRaises(ValueError):
            self.tool.build_records_from_entry(bad)

    def test_seed_entry_without_any_advisory_id_raises(self) -> None:
        bad = {
            "cve_id": "n/a",
            "ghsa_id": "n/a",
            "year": 2026,
            "title": "No-advisory entry",
            "attacker_action_sequence": "x",
            "fix_pattern": "y",
            "fix_anti_pattern": "z",
            "attack_class": "bug",
            "bug_class": "bug",
            "severity": "low",
            "preconditions": ["p"],
            "fixed_versions": "1",
            "reference_urls": ["https://example.com"],
        }
        with self.assertRaises(ValueError):
            self.tool.build_records_from_entry(bad)

    def test_target_language_only_solidity_or_vyper(self) -> None:
        records = self.tool.build_all_records()
        langs = {r["target_language"] for r in records}
        self.assertTrue(langs.issubset({"solidity", "vyper"}), f"unexpected languages: {langs}")

    def test_cross_language_analogues_never_same_language(self) -> None:
        records = self.tool.build_all_records()
        for record in records:
            for analogue in record["cross_language_analogues"]:
                self.assertNotEqual(
                    analogue["target_language"],
                    record["target_language"],
                    f"{record['record_id']} has same-language cross-language analogue",
                )


if __name__ == "__main__":
    unittest.main()
