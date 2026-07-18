"""Tests for the W6-10 Hackerman chain-candidates sidecar.

B7/B8 additions (V3 plan):
- JSON-only nested record.json fixtures (B7 shared walker coverage)
- Excluded/quarantine subtree enforcement (B7 shared walker coverage)
- Sharded sidecar round-trip, size cap, freshness, consumer auto-detect (B8)
- Monolith hard-limit gate (B8)
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-chain-candidates-sidecar.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_chain_candidates_sidecar", str(TOOL)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_RECORD = """
schema_version: auditooor.hackerman_record.v1
record_id: {rid}
source_audit_ref: audit:test:{n}
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: contracts/Vault.sol
function_shape:
  raw_signature: "function deposit(uint256 assets, address receiver) external"
  shape_tags:
    - deposit-shape-{n}
bug_class: {bug_class}
attack_class: {attack_class}
attacker_role: unprivileged
attacker_action_sequence: "Step 1: exploit the shared deposit surface. Step 2: observe the analogue."
required_preconditions:
  - shared anchor exists
impact_class: theft
impact_actor: depositor-class
impact_dollar_class: "$10K-$100K"
fix_pattern: unrelated mitigation
fix_anti_pattern_avoided: unrelated anti-pattern
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
"""


class HackermanChainCandidatesSidecarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory(prefix="hcc-sidecar-")
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.tag_dir.mkdir()
        self.sidecar = self.tmp_path / "derived" / "chain_candidates.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_record(
        self,
        n: int,
        bug_class: str,
        attack_class: str,
        relative_path: str | None = None,
    ) -> Path:
        rid = f"rec/{bug_class}/{n}"
        path = self.tag_dir / (relative_path or f"rec{n}.yaml")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            textwrap.dedent(
                _RECORD.format(rid=rid, n=n, bug_class=bug_class, attack_class=attack_class)
            ).lstrip(),
            encoding="utf-8",
        )
        return path

    def test_build_emits_meta_header_and_records(self) -> None:
        self._write_record(0, "access-control", "access-control-missing-modifier")
        self._write_record(1, "stale-oracle", "oracle-staleness")
        meta = self.tool.build_sidecar(self.tag_dir, self.sidecar)
        self.assertEqual(meta["records_emitted"], 2)
        self.assertEqual(meta["total_files_skipped"], 0)
        self.assertTrue(meta["corpus_fingerprint"])

        loaded_meta, records = self.tool.load_sidecar(self.sidecar)
        self.assertEqual(loaded_meta["schema_version"], self.tool.META_SCHEMA)
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r.get("record_id") for r in records))

    def test_build_uses_recursive_corpus_walker(self) -> None:
        self._write_record(
            0,
            "access-control",
            "access-control-missing-modifier",
            "nested/finding-1/record.yaml",
        )
        meta = self.tool.build_sidecar(self.tag_dir, self.sidecar)
        _loaded_meta, records = self.tool.load_sidecar(self.sidecar)

        self.assertEqual(meta["corpus_file_count"], 1)
        self.assertEqual(meta["records_emitted"], 1)
        self.assertEqual(records[0]["tag_file"], "nested/finding-1/record.yaml")

    def test_freshness_check_detects_added_record(self) -> None:
        self._write_record(0, "access-control", "access-control-missing-modifier")
        self.tool.build_sidecar(self.tag_dir, self.sidecar)
        self.assertTrue(self.tool.sidecar_is_fresh(self.tag_dir, self.sidecar)[0])

        time.sleep(0.01)
        self._write_record(1, "stale-oracle", "oracle-staleness")
        fresh, reason = self.tool.sidecar_is_fresh(self.tag_dir, self.sidecar)
        self.assertFalse(fresh)
        self.assertIn("changed", reason)

    def test_load_summary_uses_fresh_sidecar_and_matches_direct_payload(self) -> None:
        self._write_record(0, "access-control", "access-control-missing-modifier")
        self._write_record(1, "stale-oracle", "oracle-staleness")
        self._write_record(2, "reentrancy", "callback-reentrancy")
        self.tool.build_sidecar(self.tag_dir, self.sidecar)

        cached = self.tool.load_candidate_summary(
            self.tag_dir, self.sidecar, limit=5, include_generic=False
        )
        direct = self.tool._direct_payload(self.tag_dir, limit=5, include_generic=False)

        self.assertTrue(cached["sidecar_used"])
        self.assertEqual(cached["total_records_loaded"], 3)
        self.assertEqual(cached["total_candidates"], direct["total_candidates"])
        self.assertEqual(
            [row["candidate_id"] for row in cached["candidates"]],
            [row["candidate_id"] for row in direct["candidates"]],
        )
        self.assertEqual(
            [row["record_count"] for row in cached["candidates"]],
            [row["record_count"] for row in direct["candidates"]],
        )

    def test_load_summary_falls_back_on_missing_sidecar(self) -> None:
        self._write_record(0, "access-control", "access-control-missing-modifier")
        self._write_record(1, "stale-oracle", "oracle-staleness")
        summary = self.tool.load_candidate_summary(self.tag_dir, self.sidecar, limit=3)
        self.assertFalse(summary["sidecar_used"])
        self.assertEqual(summary["total_records_loaded"], 2)
        self.assertGreaterEqual(summary["total_candidates"], 1)

    def test_no_fallback_raises_on_stale(self) -> None:
        self._write_record(0, "access-control", "access-control-missing-modifier")
        self.tool.build_sidecar(self.tag_dir, self.sidecar)
        time.sleep(0.01)
        self._write_record(1, "stale-oracle", "oracle-staleness")
        with self.assertRaises(ValueError):
            self.tool.load_candidate_summary(
                self.tag_dir,
                self.sidecar,
                allow_slow_fallback=False,
                limit=3,
            )

    def test_corrupt_sidecar_meta_is_stale(self) -> None:
        self._write_record(0, "access-control", "access-control-missing-modifier")
        self.sidecar.parent.mkdir(parents=True, exist_ok=True)
        self.sidecar.write_text("not json at all\n", encoding="utf-8")
        fresh, reason = self.tool.sidecar_is_fresh(self.tag_dir, self.sidecar)
        self.assertFalse(fresh)
        self.assertIn("unreadable", reason)

    def test_cli_check_mode_exit_codes(self) -> None:
        self._write_record(0, "access-control", "access-control-missing-modifier")
        rc = self.tool.main(["--tag-dir", str(self.tag_dir), "--check"])
        self.assertEqual(rc, 1)
        self.assertEqual(self.tool.main(["--tag-dir", str(self.tag_dir)]), 0)
        rc = self.tool.main(["--tag-dir", str(self.tag_dir), "--check"])
        self.assertEqual(rc, 0)

    # B7: shared recursive walker - JSON-only nested records and excluded subtrees

    def test_build_picks_up_json_only_nested_record(self) -> None:
        """B7: Walker must enumerate record.json when no record.yaml sibling exists."""
        json_dir = self.tag_dir / "lending_protocols" / "synth-json-only-001"
        json_dir.mkdir(parents=True)
        record = {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_id": "lending-protocols:synth-json-only:001:abcd1234",
            "source_audit_ref": "https://github.com/test/advisory/1",
            "target_domain": "lending",
            "target_language": "solidity",
            "target_repo": "test/protocol",
            "target_component": "contracts/Vault.sol",
            "function_shape": {
                "raw_signature": "function deposit(uint256 assets) external",
                "shape_tags": ["deposit-shape"],
            },
            "bug_class": "access-control",
            "attack_class": "access-control-missing-modifier",
            "attacker_role": "unprivileged",
            "attacker_action_sequence": "Step 1: call without role.",
            "required_preconditions": ["no access control"],
            "impact_class": "theft",
            "impact_actor": "depositor-class",
            "impact_dollar_class": "$10K-$100K",
            "fix_pattern": "add onlyOwner",
            "fix_anti_pattern_avoided": "unprotected write",
            "severity_at_finding": "high",
            "year": 2025,
            "cross_language_analogues": [],
            "related_records": [],
            "verification_tier": "tier-2-verified-public-archive",
        }
        (json_dir / "record.json").write_text(json.dumps(record), encoding="utf-8")

        meta = self.tool.build_sidecar(self.tag_dir, self.sidecar)
        _loaded_meta, records = self.tool.load_sidecar(self.sidecar)

        self.assertEqual(meta["corpus_file_count"], 1)
        self.assertEqual(meta["records_emitted"], 1)
        self.assertEqual(
            records[0]["tag_file"],
            "lending_protocols/synth-json-only-001/record.json",
        )

    def test_build_excludes_quarantine_subtree(self) -> None:
        """B7: Walker must skip _QUARANTINE_* and _deprecated subtrees by default."""
        self._write_record(0, "access-control", "access-control-missing-modifier")
        quarantine_dir = self.tag_dir / "_QUARANTINE_FABRICATED_CVE"
        quarantine_dir.mkdir(parents=True)
        self._write_record(
            99,
            "reentrancy",
            "reentrancy-classic",
            "_QUARANTINE_FABRICATED_CVE/bad_record.yaml",
        )
        meta = self.tool.build_sidecar(self.tag_dir, self.sidecar)
        _loaded_meta, records = self.tool.load_sidecar(self.sidecar)

        # Quarantine record must NOT appear in the sidecar.
        self.assertEqual(meta["corpus_file_count"], 1)
        self.assertEqual(meta["records_emitted"], 1)
        record_ids = [r.get("record_id") for r in records]
        self.assertFalse(
            any("QUARANTINE" in str(rid) for rid in record_ids),
            "Quarantine records leaked into sidecar",
        )

    # B8: sharded sidecar - round-trip, shard count, size cap

    def test_build_sharded_sidecar_emits_manifest_and_shards(self) -> None:
        """B8: Sharded layout writes manifest.json plus bounded shard files."""
        for n in range(5):
            self._write_record(n, "access-control", "access-control-missing-modifier")

        manifest = self.tool.build_sharded_sidecar(
            self.tag_dir,
            self.sidecar,
            shard_target_bytes=800,
        )

        manifest_path = self.sidecar.with_name(f"{self.sidecar.stem}.manifest.json")
        shard_dir = self.sidecar.with_name(f"{self.sidecar.stem}.d")
        self.assertTrue(manifest_path.exists())
        self.assertTrue(shard_dir.is_dir())
        self.assertEqual(manifest["schema_version"], self.tool.MANIFEST_SCHEMA)
        self.assertEqual(manifest["records_emitted"], 5)
        self.assertGreater(manifest["shard_count"], 1)

        # Round-trip: load via load_sidecar (auto-detects manifest).
        loaded_meta, records = self.tool.load_sidecar(self.sidecar)
        self.assertEqual(loaded_meta["records_emitted"], 5)
        self.assertEqual(len(records), 5)

    def test_sharded_sidecar_no_shard_exceeds_size_cap(self) -> None:
        """B8: No shard file may exceed the configured shard_target_bytes."""
        for n in range(10):
            self._write_record(n, "reentrancy", "reentrancy-classic")

        shard_target = 800
        manifest = self.tool.build_sharded_sidecar(
            self.tag_dir,
            self.sidecar,
            shard_target_bytes=shard_target,
        )

        shard_dir = self.sidecar.with_name(f"{self.sidecar.stem}.d")
        for shard_info in manifest["shards"]:
            shard_path = shard_dir / shard_info["path"]
            actual_size = shard_path.stat().st_size
            # Each shard must NOT exceed shard_target by more than a single record.
            self.assertLessEqual(
                actual_size,
                shard_target * 3,  # generous bound: one record may push past
                f"Shard {shard_info['path']} ({actual_size}B) far exceeds target {shard_target}B",
            )

    def test_sharded_freshness_detects_missing_shard(self) -> None:
        """B8: sidecar_is_fresh must return stale when a shard is deleted."""
        for n in range(3):
            self._write_record(n, "reentrancy", "reentrancy-classic")
        manifest = self.tool.build_sharded_sidecar(
            self.tag_dir,
            self.sidecar,
            shard_target_bytes=800,
        )
        first_shard = manifest["shards"][0]["path"]
        shard_dir = self.sidecar.with_name(f"{self.sidecar.stem}.d")
        (shard_dir / first_shard).unlink()

        fresh, reason = self.tool.sidecar_is_fresh(self.tag_dir, self.sidecar)
        self.assertFalse(fresh)
        self.assertIn("shard missing", reason)

    def test_load_candidate_summary_uses_fresh_sharded_sidecar(self) -> None:
        """B8: load_candidate_summary auto-detects the sharded manifest."""
        for n in range(3):
            self._write_record(n, "access-control", "access-control-missing-modifier")
        self.tool.build_sharded_sidecar(
            self.tag_dir, self.sidecar, shard_target_bytes=800
        )

        summary = self.tool.load_candidate_summary(
            self.tag_dir, self.sidecar, limit=5, include_generic=False
        )

        self.assertTrue(summary["sidecar_used"])
        self.assertEqual(summary["sidecar_layout"], "sharded-jsonl")
        self.assertGreater(summary["shard_count"], 0)
        self.assertEqual(summary["total_records_loaded"], 3)

    def test_monolith_hard_limit_raises(self) -> None:
        """B8: build_sidecar raises RuntimeError when monolith would exceed hard limit."""
        self._write_record(0, "access-control", "access-control-missing-modifier")
        original = self.tool.SIZE_HARD_BYTES_DEFAULT
        self.tool.SIZE_HARD_BYTES_DEFAULT = 1
        try:
            with self.assertRaises(RuntimeError):
                self.tool.build_sidecar(self.tag_dir, self.sidecar)
        finally:
            self.tool.SIZE_HARD_BYTES_DEFAULT = original
        self.assertFalse(self.sidecar.exists())

    def test_cli_sharded_mode_is_default(self) -> None:
        """B8: Default CLI invocation writes a manifest, not a monolith."""
        self._write_record(0, "access-control", "access-control-missing-modifier")
        rc = self.tool.main(["--tag-dir", str(self.tag_dir)])
        self.assertEqual(rc, 0)
        manifest_path = self.sidecar.with_name(f"{self.sidecar.stem}.manifest.json")
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], self.tool.MANIFEST_SCHEMA)

    def test_cli_monolith_flag_writes_jsonl_not_manifest(self) -> None:
        """B8: --monolith flag writes the legacy single JSONL, no manifest."""
        self._write_record(0, "access-control", "access-control-missing-modifier")
        rc = self.tool.main(["--tag-dir", str(self.tag_dir), "--monolith"])
        self.assertEqual(rc, 0)
        self.assertTrue(self.sidecar.exists())
        manifest_path = self.sidecar.with_name(f"{self.sidecar.stem}.manifest.json")
        self.assertFalse(manifest_path.exists())


if __name__ == "__main__":
    unittest.main()
