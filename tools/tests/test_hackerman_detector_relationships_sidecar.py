from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SIDECAR_TOOL = REPO_ROOT / "tools" / "hackerman-detector-relationships-sidecar.py"
REL_TOOL = REPO_ROOT / "tools" / "hackerman-detector-relationships.py"
FIXTURES = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_records"


def _load_tool(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


CUSTOM_REENTRANCY_RECORD = textwrap.dedent(
    """\
    schema_version: auditooor.hackerman_record.v1
    record_id: custom:reentrancy-withdraw:1111aaaa
    source_audit_ref: custom:reentrancy-withdraw
    target_domain: lending
    target_language: solidity
    target_repo: sample/vault
    target_component: Vault.withdraw
    function_shape:
      raw_signature: "function withdraw(uint256 assets) external"
      shape_tags:
        - withdraw-callback
        - external-withdraw
    bug_class: reentrancy
    attack_class: reentrancy-via-hook-or-callback
    attacker_role: unprivileged
    attacker_action_sequence: "Step 1: withdraw. Step 2: reenter via callback."
    required_preconditions:
      - callback-enabled token
    impact_class: theft
    impact_actor: liquidity-providers
    impact_dollar_class: "$10K-$100K"
    fix_pattern: move accounting before external callback and lock reentry
    fix_anti_pattern_avoided: external callback before accounting
    severity_at_finding: high
    year: 2025
    cross_language_analogues: []
    related_records: []
    """
)


class HackermanDetectorRelationshipsSidecarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sidecar = _load_tool(
            SIDECAR_TOOL, "_hackerman_detector_relationships_sidecar_test"
        )
        cls.relationships = _load_tool(
            REL_TOOL, "_hackerman_detector_relationships_test"
        )

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="hdr-sidecar-")
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.tag_dir.mkdir()
        self.sidecar_path = (
            self.tmp_path / "derived" / "detector_relationship_records.jsonl"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _build_tag_dir(self) -> None:
        shutil.copy(
            FIXTURES / "valid_lending_share_inflation.yaml",
            self.tag_dir / "valid_lending_share_inflation.yaml",
        )
        shutil.copy(
            FIXTURES / "valid_go_fee_bypass.yml",
            self.tag_dir / "valid_go_fee_bypass.yml",
        )
        (self.tag_dir / "custom_reentrancy.yaml").write_text(
            CUSTOM_REENTRANCY_RECORD, encoding="utf-8"
        )

    def _write_engage_report(self) -> Path:
        path = self.tmp_path / "engage_report.json"
        path.write_text(
            json.dumps(
                {
                    "clusters": [
                        {
                            "detector_slug": "deposit-share-inflation",
                            "hits": [
                                {
                                    "severity": "HIGH",
                                    "file_path": "src/EVault.sol:55",
                                    "snippet": "deposit mints shares from live balance after attacker donation",
                                }
                            ],
                        },
                        {
                            "detector_slug": "blocked-addr-check-missing",
                            "hits": [
                                {
                                    "severity": "MEDIUM",
                                    "file_path": "x/affiliates/keeper/keeper.go:88",
                                    "snippet": "keeper writes affiliate recipient without blocked address validation",
                                }
                            ],
                        },
                        {
                            "detector_slug": "reentrancy-no-guard",
                            "hits": [
                                {
                                    "severity": "HIGH",
                                    "file_path": "src/Vault.sol:42",
                                    "snippet": "withdraw callback path lacks reentrancy guard before accounting update",
                                }
                            ],
                        },
                    ]
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def _direct_payload(self, engage_report: Path, limit: int = 3) -> dict[str, object]:
        args = self.relationships.build_parser().parse_args(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--engage-report",
                str(engage_report),
                "--limit",
                str(limit),
            ]
        )
        return self.relationships.build_payload(args)

    def test_build_emits_meta_header_and_records(self) -> None:
        self._build_tag_dir()
        meta = self.sidecar.build_sidecar(self.tag_dir, self.sidecar_path)
        self.assertEqual(meta["records_loaded"], 3)
        self.assertEqual(meta["records_skipped_invalid"], 0)
        self.assertEqual(meta["records_skipped_non_record"], 0)
        self.assertTrue(meta["generated_at_utc"])

        loaded_meta, records = self.sidecar.load_sidecar(self.sidecar_path)
        self.assertEqual(loaded_meta["schema_version"], self.sidecar.META_SCHEMA)
        self.assertEqual(loaded_meta["generated_at_utc"], meta["generated_at_utc"])
        self.assertEqual(len(records), 3)
        self.assertTrue(all(row.get("record_id") for row in records))
        self.assertTrue(all("attack_terms" in row for row in records))

    def test_build_uses_recursive_corpus_walker(self) -> None:
        nested = self.tag_dir / "nested" / "finding-1"
        nested.mkdir(parents=True)
        (nested / "record.yaml").write_text(CUSTOM_REENTRANCY_RECORD, encoding="utf-8")

        meta = self.sidecar.build_sidecar(self.tag_dir, self.sidecar_path)
        _loaded_meta, records = self.sidecar.load_sidecar(self.sidecar_path)

        self.assertEqual(meta["corpus_file_count"], 1)
        self.assertEqual(meta["records_loaded"], 1)
        self.assertEqual(records[0]["file_name"], "nested/finding-1/record.yaml")

    def test_freshness_detects_added_record(self) -> None:
        self._build_tag_dir()
        self.sidecar.build_sidecar(self.tag_dir, self.sidecar_path)
        self.assertTrue(
            self.sidecar.sidecar_is_fresh(self.tag_dir, self.sidecar_path)[0]
        )

        time.sleep(0.01)
        shutil.copy(
            FIXTURES / "valid_lending_share_inflation.yaml",
            self.tag_dir / "extra.yaml",
        )
        fresh, reason = self.sidecar.sidecar_is_fresh(self.tag_dir, self.sidecar_path)
        self.assertFalse(fresh)
        self.assertIn("changed", reason)

    def test_load_summary_uses_fresh_sidecar_and_matches_direct_payload(self) -> None:
        self._build_tag_dir()
        engage_report = self._write_engage_report()
        self.sidecar.build_sidecar(self.tag_dir, self.sidecar_path)

        cached = self.sidecar.load_relationship_summary(
            self.tag_dir,
            str(engage_report),
            self.sidecar_path,
            limit=3,
        )
        direct = self._direct_payload(engage_report, limit=3)

        self.assertTrue(cached["sidecar_used"])
        self.assertEqual(cached["summary"]["records_loaded"], 3)
        self.assertEqual(
            [row["detector_slug"] for row in cached["detectors"]],
            [row["detector_slug"] for row in direct["detectors"]],
        )
        self.assertEqual(
            [
                [rel["record_id"] for rel in row["relationships"]]
                for row in cached["detectors"]
            ],
            [
                [rel["record_id"] for rel in row["relationships"]]
                for row in direct["detectors"]
            ],
        )
        self.assertEqual(
            cached["summary"]["relationship_rows_returned"],
            direct["summary"]["relationship_rows_returned"],
        )

    def test_load_summary_defaults_to_tag_dir_sibling_sidecar(self) -> None:
        self._build_tag_dir()
        engage_report = self._write_engage_report()
        default_path = self.sidecar._default_sidecar_path(self.tag_dir)
        self.sidecar.build_sidecar(self.tag_dir, default_path)

        cached = self.sidecar.load_relationship_summary(
            self.tag_dir,
            str(engage_report),
            limit=3,
        )

        self.assertTrue(cached["sidecar_used"])
        self.assertEqual(cached["sidecar_status"], "fresh")
        self.assertEqual(cached["sidecar_path"], str(default_path))
        self.assertEqual(cached["summary"]["records_loaded"], 3)

    def test_load_summary_falls_back_on_missing_sidecar(self) -> None:
        self._build_tag_dir()
        engage_report = self._write_engage_report()
        payload = self.sidecar.load_relationship_summary(
            self.tag_dir,
            str(engage_report),
            self.sidecar_path,
            limit=2,
        )
        self.assertFalse(payload["sidecar_used"])
        self.assertEqual(payload["summary"]["records_loaded"], 3)
        self.assertEqual(payload["summary"]["detectors_returned"], 2)

    def test_no_fallback_raises_on_stale(self) -> None:
        self._build_tag_dir()
        engage_report = self._write_engage_report()
        self.sidecar.build_sidecar(self.tag_dir, self.sidecar_path)

        time.sleep(0.01)
        shutil.copy(
            FIXTURES / "valid_lending_share_inflation.yaml",
            self.tag_dir / "extra.yaml",
        )
        with self.assertRaises(ValueError):
            self.sidecar.load_relationship_summary(
                self.tag_dir,
                str(engage_report),
                self.sidecar_path,
                allow_slow_fallback=False,
                limit=2,
            )

    def test_cli_check_mode_exit_codes(self) -> None:
        self._build_tag_dir()
        rc = self.sidecar.main(
            ["--tag-dir", str(self.tag_dir), "--out", str(self.sidecar_path), "--check"]
        )
        self.assertEqual(rc, 1)
        self.assertEqual(
            self.sidecar.main(
                ["--tag-dir", str(self.tag_dir), "--out", str(self.sidecar_path)]
            ),
            0,
        )
        rc = self.sidecar.main(
            ["--tag-dir", str(self.tag_dir), "--out", str(self.sidecar_path), "--check"]
        )
        self.assertEqual(rc, 0)

    # B7: shared recursive walker - JSON-only nested records and excluded subtrees

    def test_build_picks_up_json_only_nested_record(self) -> None:
        """B7: Walker must enumerate record.json when no record.yaml sibling exists."""
        json_dir = self.tag_dir / "lending_protocols" / "synth-json-only-dr-001"
        json_dir.mkdir(parents=True)
        record = {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_id": "lending-protocols:synth-dr-json:001:deadbeef",
            "source_audit_ref": "https://github.com/test/advisory/dr-1",
            "target_domain": "lending",
            "target_language": "solidity",
            "target_repo": "test/protocol",
            "target_component": "contracts/Vault.sol",
            "function_shape": {
                "raw_signature": "function withdraw(uint256 assets) external",
                "shape_tags": ["withdraw-callback"],
            },
            "bug_class": "reentrancy",
            "attack_class": "reentrancy-via-hook-or-callback",
            "attacker_role": "unprivileged",
            "attacker_action_sequence": "Step 1: withdraw. Step 2: reenter.",
            "required_preconditions": ["callback-enabled token"],
            "impact_class": "theft",
            "impact_actor": "depositor-class",
            "impact_dollar_class": "$10K-$100K",
            "fix_pattern": "CEI pattern",
            "fix_anti_pattern_avoided": "external call before accounting",
            "severity_at_finding": "high",
            "year": 2025,
            "cross_language_analogues": [],
            "related_records": [],
            "verification_tier": "tier-2-verified-public-archive",
        }
        (json_dir / "record.json").write_text(json.dumps(record), encoding="utf-8")

        meta = self.sidecar.build_sidecar(self.tag_dir, self.sidecar_path)
        _loaded_meta, records = self.sidecar.load_sidecar(self.sidecar_path)

        self.assertEqual(meta["corpus_file_count"], 1)
        self.assertEqual(meta["records_loaded"], 1)
        self.assertEqual(
            records[0]["file_name"],
            "lending_protocols/synth-json-only-dr-001/record.json",
        )

    def test_build_excludes_quarantine_subtree(self) -> None:
        """B7: Walker must skip _QUARANTINE_* subtrees by default."""
        self._build_tag_dir()
        quarantine_dir = self.tag_dir / "_QUARANTINE_FABRICATED_CVE"
        quarantine_dir.mkdir(parents=True)
        (quarantine_dir / "bad_record.yaml").write_text(CUSTOM_REENTRANCY_RECORD, encoding="utf-8")

        meta = self.sidecar.build_sidecar(self.tag_dir, self.sidecar_path)
        _loaded_meta, records = self.sidecar.load_sidecar(self.sidecar_path)

        # The 3 valid records must be present; quarantine must be absent.
        self.assertEqual(meta["records_loaded"], 3)
        record_ids = [r.get("record_id") for r in records]
        self.assertFalse(
            any("QUARANTINE" in str(rid) for rid in record_ids),
            "Quarantine records leaked into sidecar",
        )

    # B8: sharded sidecar - round-trip, shard count, size cap

    def test_build_sharded_sidecar_emits_manifest_and_shards(self) -> None:
        """B8: Sharded layout writes manifest.json plus bounded shard files."""
        self._build_tag_dir()

        # Use a very small target (200B) to force multiple shards across 3 records.
        manifest = self.sidecar.build_sharded_sidecar(
            self.tag_dir,
            self.sidecar_path,
            shard_target_bytes=200,
        )

        manifest_path = self.sidecar_path.with_name(
            f"{self.sidecar_path.stem}.manifest.json"
        )
        shard_dir = self.sidecar_path.with_name(f"{self.sidecar_path.stem}.d")
        self.assertTrue(manifest_path.exists())
        self.assertTrue(shard_dir.is_dir())
        self.assertEqual(manifest["schema_version"], self.sidecar.MANIFEST_SCHEMA)
        self.assertEqual(manifest["records_loaded"], 3)
        self.assertGreater(manifest["shard_count"], 1)

        # Round-trip via load_sidecar auto-detect.
        loaded_meta, records = self.sidecar.load_sidecar(self.sidecar_path)
        self.assertEqual(loaded_meta["records_loaded"], 3)
        self.assertEqual(len(records), 3)

    def test_sharded_sidecar_no_shard_exceeds_size_cap(self) -> None:
        """B8: No shard file exceeds the configured shard_target_bytes by a large margin."""
        self._build_tag_dir()
        shard_target = 200  # force multi-shard
        manifest = self.sidecar.build_sharded_sidecar(
            self.tag_dir,
            self.sidecar_path,
            shard_target_bytes=shard_target,
        )
        shard_dir = self.sidecar_path.with_name(f"{self.sidecar_path.stem}.d")
        for shard_info in manifest["shards"]:
            shard_path = shard_dir / shard_info["path"]
            actual_size = shard_path.stat().st_size
            self.assertLessEqual(
                actual_size,
                shard_target * 20,  # generous bound: one record may push past
                f"Shard {shard_info['path']} ({actual_size}B) far exceeds target {shard_target}B",
            )

    def test_sharded_freshness_detects_missing_shard(self) -> None:
        """B8: sidecar_is_fresh must return stale when a shard is deleted."""
        self._build_tag_dir()
        manifest = self.sidecar.build_sharded_sidecar(
            self.tag_dir,
            self.sidecar_path,
            shard_target_bytes=200,  # force multi-shard
        )
        first_shard = manifest["shards"][0]["path"]
        shard_dir = self.sidecar_path.with_name(f"{self.sidecar_path.stem}.d")
        (shard_dir / first_shard).unlink()

        fresh, reason = self.sidecar.sidecar_is_fresh(self.tag_dir, self.sidecar_path)
        self.assertFalse(fresh)
        self.assertIn("shard missing", reason)

    def test_monolith_hard_limit_raises(self) -> None:
        """B8: build_sidecar raises RuntimeError when monolith would exceed hard limit."""
        self._build_tag_dir()
        original = self.sidecar.SIZE_HARD_BYTES_DEFAULT
        self.sidecar.SIZE_HARD_BYTES_DEFAULT = 1
        try:
            with self.assertRaises(RuntimeError):
                self.sidecar.build_sidecar(self.tag_dir, self.sidecar_path)
        finally:
            self.sidecar.SIZE_HARD_BYTES_DEFAULT = original
        self.assertFalse(self.sidecar_path.exists())

    def test_cli_sharded_mode_is_default(self) -> None:
        """B8: Default CLI invocation writes a manifest, not a monolith."""
        self._build_tag_dir()
        rc = self.sidecar.main(
            ["--tag-dir", str(self.tag_dir), "--out", str(self.sidecar_path)]
        )
        self.assertEqual(rc, 0)
        manifest_path = self.sidecar_path.with_name(
            f"{self.sidecar_path.stem}.manifest.json"
        )
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], self.sidecar.MANIFEST_SCHEMA)

    def test_cli_monolith_flag_writes_jsonl_not_manifest(self) -> None:
        """B8: --monolith flag writes the legacy single JSONL, no manifest."""
        self._build_tag_dir()
        rc = self.sidecar.main(
            ["--tag-dir", str(self.tag_dir), "--out", str(self.sidecar_path), "--monolith"]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(self.sidecar_path.exists())
        manifest_path = self.sidecar_path.with_name(
            f"{self.sidecar_path.stem}.manifest.json"
        )
        self.assertFalse(manifest_path.exists())


if __name__ == "__main__":
    unittest.main()
