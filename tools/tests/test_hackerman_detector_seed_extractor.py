"""Tests for tools/hackerman-detector-seed-extractor.py.

The extractor walks per-directory record bundles under
``audit/corpus_tags/tags/<bucket>/<slug>/record.{json,yaml}``, filters
to tier-1 + tier-2 (real-source) records, and emits a *preview* JSONL
artifact plus a markdown summary. These tests build small synthetic tag
trees and call the loaded module directly so they remain fast and
deterministic.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any, Dict


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-detector-seed-extractor.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_detector_seed_extractor", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _write_record_json(slug_dir: Path, payload: Dict[str, Any]) -> None:
    slug_dir.mkdir(parents=True, exist_ok=True)
    (slug_dir / "record.json").write_text(
        json.dumps(payload, sort_keys=True), encoding="utf-8"
    )


def _ghsa_record(slug: str, attack_class: str, tags: list) -> Dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"cosmos-sdk-ibc:cometbft-cometbft:ghsa-{slug}:abcdef012345",
        "source_audit_ref": f"https://github.com/cometbft/cometbft/security/advisories/GHSA-{slug}",
        "target_repo": "cometbft/cometbft",
        "target_language": "go",
        "attack_class": attack_class,
        "function_shape": {"shape_tags": tags},
        "source_extraction_method": "corpus-etl",
    }


def _dex_fix_record(slug: str, attack_class: str, tags: list) -> Dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"dex-fix-history:balancer-balancer-v2-monorepo:{slug}:cb62623b3dfe",
        "source_audit_ref": f"github:balancer/balancer-v2-monorepo@{slug}",
        "target_repo": "balancer/balancer-v2-monorepo",
        "target_language": "solidity",
        "attack_class": attack_class,
        "function_shape": {"shape_tags": tags},
        "source_extraction_method": "corpus-etl",
    }


def _synthetic_record(slug: str, attack_class: str, tags: list) -> Dict[str, Any]:
    """Tier-4 dsl-synthetic record. Must be skipped by the extractor."""
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"dsl-pattern:{slug}",
        "source_audit_ref": f"dsl-pattern:{slug}",
        "target_repo": "unknown/dsl-synthetic",
        "target_language": "solidity",
        "attack_class": attack_class,
        "function_shape": {"shape_tags": tags},
        "source_extraction_method": "dsl-synthetic",
    }


class TierClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_tool()

    def test_ghsa_advisory_is_tier1(self) -> None:
        rec = _ghsa_record("hrhf-2vcr-ghch", "ghsa-public-advisory-go", ["ghsa-hrhf-2vcr-ghch"])
        tier, _reason = self.mod.classify_tier(rec)
        self.assertEqual(tier, "tier-1-verified-realtime-api")
        self.assertTrue(self.mod.is_real_source_tier(tier))

    def test_github_sha_source_ref_is_tier1(self) -> None:
        rec = _dex_fix_record("2a698757abc1", "external-call-reentrancy", ["reentrancy"])
        tier, _reason = self.mod.classify_tier(rec)
        self.assertEqual(tier, "tier-1-verified-realtime-api")

    def test_zkbugs_prefix_is_tier1(self) -> None:
        rec = {
            "record_id": "zkbugs:0xbok/circom-bigint/veridise-V-BIGINT-COD-001:abc",
            "source_audit_ref": "zkbugs:zksecurity/zkbugs:0xbok/circom-bigint/...",
            "function_shape": {"shape_tags": ["unconstrained-variable"]},
            "attack_class": "unconstrained-variable",
            "source_extraction_method": "corpus-etl",
        }
        tier, _reason = self.mod.classify_tier(rec)
        self.assertEqual(tier, "tier-1-verified-realtime-api")

    def test_dsl_synthetic_is_tier4_skipped(self) -> None:
        rec = _synthetic_record("oracle-stale-no-revert", "stale-oracle", ["stale-oracle"])
        tier, _reason = self.mod.classify_tier(rec)
        self.assertEqual(tier, "tier-4-bundled-fixture")
        self.assertFalse(self.mod.is_real_source_tier(tier))

    def test_corpus_mined_is_tier3_skipped(self) -> None:
        rec = {
            "record_id": "corpus-mined:slice-aa:l18-s1",
            "source_audit_ref": "corpus-mined:slice-aa:l18-s1",
            "function_shape": {"shape_tags": ["reentrancy"]},
            "attack_class": "reentrancy",
            "source_extraction_method": "regex-derived",
        }
        tier, _reason = self.mod.classify_tier(rec)
        self.assertEqual(tier, "tier-3-synthetic-taxonomy-anchored")
        self.assertFalse(self.mod.is_real_source_tier(tier))

    def test_quarantine_marker_is_tier5(self) -> None:
        rec = {
            "record_id": "_quarantine_fabricated:cve-2099-9999",
            "source_audit_ref": "fabricated",
            "function_shape": {"shape_tags": ["fake-tag"]},
            "attack_class": "fabricated",
            "source_extraction_method": "corpus-etl",
        }
        tier, _reason = self.mod.classify_tier(rec)
        self.assertEqual(tier, "tier-5-quarantine")


class SeedExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_tool()
        self._tmp = tempfile.TemporaryDirectory()
        self.tags_dir = Path(self._tmp.name) / "tags"
        self.tags_dir.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_regex_seeds_require_min_recurrence(self) -> None:
        # 3 GHSA records all sharing the tag `consensus-halt`. With min=3 it
        # passes; with min=4 it is dropped.
        bucket = self.tags_dir / "cosmos_sdk_ibc"
        for i in range(3):
            _write_record_json(
                bucket / f"slug-{i}",
                _ghsa_record(
                    f"sl{i}-test",
                    "ghsa-public-advisory-go-cosmos-ibc-stack",
                    ["consensus-halt", f"unique-{i}"],
                ),
            )
        rep_lo = self.mod.extract_seeds(self.tags_dir, min_recurrence=3)
        seeds_lo = {r["seed"] for r in rep_lo["regex_seeds"]}
        self.assertIn("consensus-halt", seeds_lo)
        # unique-* tags appear only once each - should be filtered out
        self.assertNotIn("unique-0", seeds_lo)

        rep_hi = self.mod.extract_seeds(self.tags_dir, min_recurrence=4)
        seeds_hi = {r["seed"] for r in rep_hi["regex_seeds"]}
        self.assertNotIn("consensus-halt", seeds_hi)

    def test_skips_tier4_synthetic_even_if_tag_recurs(self) -> None:
        # 5 synthetic records sharing a tag. The extractor must drop them
        # ALL because they are tier-4 (dsl-synthetic), and the seed must
        # NOT appear in the output.
        bucket = self.tags_dir / "dsl_bucket"
        for i in range(5):
            _write_record_json(
                bucket / f"syn-{i}",
                _synthetic_record(f"syn-{i}", "stale-oracle", ["stale-oracle-loud"]),
            )
        rep = self.mod.extract_seeds(self.tags_dir, min_recurrence=3)
        seeds = {r["seed"] for r in rep["regex_seeds"]}
        self.assertNotIn("stale-oracle-loud", seeds)
        self.assertEqual(rep["stats"]["real_source_records"], 0)
        self.assertGreaterEqual(rep["stats"]["skipped_synthetic_records"], 5)

    def test_quarantine_bucket_is_walk_skipped(self) -> None:
        # A record under _QUARANTINE_FABRICATED_CVE bucket must NEVER be
        # included even if it ostensibly has tier-1 markers in its
        # record_id.
        bucket = self.tags_dir / "_QUARANTINE_FABRICATED_CVE"
        _write_record_json(
            bucket / "fake-slug",
            {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "cve_db:cve-2099-9999",
                "source_audit_ref": "https://nvd.nist.gov/cve-2099-9999",
                "function_shape": {"shape_tags": ["recurring-poison"]},
                "attack_class": "fabricated",
                "source_extraction_method": "corpus-etl",
            },
        )
        # Also one real record with a different tag to ensure the walk
        # itself works on non-quarantine buckets.
        real_bucket = self.tags_dir / "cosmos_sdk_ibc"
        for i in range(3):
            _write_record_json(
                real_bucket / f"real-{i}",
                _ghsa_record(f"ok-{i}", "ghsa-public-advisory-go", ["valid-tag"]),
            )
        rep = self.mod.extract_seeds(self.tags_dir, min_recurrence=3)
        seeds = {r["seed"] for r in rep["regex_seeds"]}
        self.assertIn("valid-tag", seeds)
        self.assertNotIn("recurring-poison", seeds)

    def test_stoplist_tags_are_dropped(self) -> None:
        bucket = self.tags_dir / "cosmos_sdk_ibc"
        for i in range(5):
            _write_record_json(
                bucket / f"s-{i}",
                _ghsa_record(f"st-{i}", "ghsa-public-advisory-go", ["go", "rust", "good-tag"]),
            )
        rep = self.mod.extract_seeds(self.tags_dir, min_recurrence=3)
        seeds = {r["seed"] for r in rep["regex_seeds"]}
        # `go` and `rust` are stoplisted; `good-tag` should be kept.
        self.assertIn("good-tag", seeds)
        self.assertNotIn("go", seeds)
        self.assertNotIn("rust", seeds)

    def test_attack_class_distribution_is_tracked(self) -> None:
        bucket = self.tags_dir / "cosmos_sdk_ibc"
        # Mixed attack classes for the same tag
        _write_record_json(
            bucket / "a", _ghsa_record("a", "ghsa-public-advisory-go", ["shared-tag"])
        )
        _write_record_json(
            bucket / "b", _ghsa_record("b", "ghsa-public-advisory-go", ["shared-tag"])
        )
        _write_record_json(
            bucket / "c", _ghsa_record("c", "different-class", ["shared-tag"])
        )
        rep = self.mod.extract_seeds(self.tags_dir, min_recurrence=3)
        seed_rows = [r for r in rep["regex_seeds"] if r["seed"] == "shared-tag"]
        self.assertEqual(len(seed_rows), 1)
        dist = seed_rows[0]["attack_class_distribution"]
        self.assertEqual(dist.get("ghsa-public-advisory-go"), 2)
        self.assertEqual(dist.get("different-class"), 1)

    def test_ast_seeds_extracted_from_code_snippet(self) -> None:
        diffs = self.mod.extract_diff_seeds(
            "\n".join(
                [
                    "context line",
                    "+ require(amount > 0);",
                    "- balanceOf[msg.sender] = 0;",
                    "+ balanceOf[msg.sender] += amount;",
                    "  unchanged",
                ]
            )
        )
        self.assertTrue(any(d.startswith("require(amount") for d in diffs))
        self.assertTrue(any(d.startswith("balanceOf[msg.sender]") for d in diffs))
        # Dedup: same line shouldn't appear twice even if it differs only in case
        again = self.mod.extract_diff_seeds("+ require(amount > 0);\n+ require(amount > 0);")
        self.assertEqual(len(again), 1)

    def test_end_to_end_writes_jsonl_and_markdown(self) -> None:
        bucket = self.tags_dir / "cosmos_sdk_ibc"
        for i in range(4):
            _write_record_json(
                bucket / f"e2e-{i}",
                _ghsa_record(f"e2e-{i}", "ghsa-public-advisory-go", ["e2e-shared"]),
            )
        out_jsonl = Path(self._tmp.name) / "out" / "candidate_detectors.jsonl"
        out_md = Path(self._tmp.name) / "docs" / "PREVIEW.md"
        rc = self.mod.main(
            [
                "--tags-dir",
                str(self.tags_dir),
                "--output-jsonl",
                str(out_jsonl),
                "--output-docs",
                str(out_md),
                "--min-recurrence",
                "3",
                "--top-n",
                "10",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(out_jsonl.exists())
        self.assertTrue(out_md.exists())
        text = out_md.read_text(encoding="utf-8")
        self.assertIn("Hackerman Detector Seeds", text)
        self.assertIn("e2e-shared", text)
        # JSONL has at least one row
        lines = [ln for ln in out_jsonl.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertGreaterEqual(len(lines), 1)
        # Each row is valid JSON
        for ln in lines:
            json.loads(ln)

    def test_dry_run_writes_nothing(self) -> None:
        bucket = self.tags_dir / "cosmos_sdk_ibc"
        for i in range(3):
            _write_record_json(
                bucket / f"dr-{i}",
                _ghsa_record(f"dr-{i}", "ghsa-public-advisory-go", ["dr-tag"]),
            )
        out_jsonl = Path(self._tmp.name) / "out" / "candidate_detectors.jsonl"
        out_md = Path(self._tmp.name) / "docs" / "PREVIEW.md"
        rc = self.mod.main(
            [
                "--tags-dir",
                str(self.tags_dir),
                "--output-jsonl",
                str(out_jsonl),
                "--output-docs",
                str(out_md),
                "--min-recurrence",
                "3",
                "--dry-run",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertFalse(out_jsonl.exists())
        self.assertFalse(out_md.exists())

    def test_missing_tags_dir_returns_2(self) -> None:
        rc = self.mod.main(
            [
                "--tags-dir",
                str(Path(self._tmp.name) / "does-not-exist"),
                "--output-jsonl",
                str(Path(self._tmp.name) / "x.jsonl"),
                "--output-docs",
                str(Path(self._tmp.name) / "x.md"),
            ]
        )
        self.assertEqual(rc, 2)

    def _write_flat_yaml(self, bucket: Path, slug: str, body: str) -> None:
        bucket.mkdir(parents=True, exist_ok=True)
        (bucket / f"{slug}.yaml").write_text(textwrap.dedent(body), encoding="utf-8")

    def test_flat_file_layout_records_are_discovered(self) -> None:
        """Guard for the mining-detectorization fix: records stored as flat
        ``<bucket>/<slug>.yaml`` files (the dominant on-disk layout, incl.
        every newly-ingested own-finding / prior-audit / solodit / github
        record) MUST be walked, not only the per-directory
        ``<slug>/record.yaml`` bundles. Pre-fix the extractor saw 0 of these.
        """
        bucket = self.tags_dir / "auditooor_prior_audits"
        for i in range(3):
            self._write_flat_yaml(
                bucket,
                f"prior-audit-flat-{i}",
                f"""\
                schema_version: auditooor.hackerman_record.v1.1
                record_id: prior-audit:mezo:report-{i}:abc{i}
                source_audit_ref: prior-audit:mezo:report-{i}
                target_repo: mezo/musd
                target_language: solidity
                attack_class: admin-bypass
                function_shape:
                  raw_signature: <unresolved>
                  shape_tags:
                    - flat-shared-tag
                    - unique-flat-{i}
                """,
            )
        rep = self.mod.extract_seeds(self.tags_dir, min_recurrence=3)
        seeds = {r["seed"] for r in rep["regex_seeds"]}
        self.assertIn("flat-shared-tag", seeds)
        # All 3 flat prior-audit records are tier-2 real-source.
        self.assertEqual(rep["stats"]["real_source_records"], 3)
        self.assertEqual(rep["stats"]["scanned_bundles"], 3)

    def test_flat_and_bundle_layouts_coexist(self) -> None:
        """A bucket mixing a flat ``<slug>.yaml`` record and a bundle
        ``<slug>/record.json`` record must contribute BOTH to the seed pool.
        """
        bucket = self.tags_dir / "cosmos_sdk_ibc"
        # 2 flat YAML records sharing a tag ...
        for i in range(2):
            self._write_flat_yaml(
                bucket,
                f"flat-{i}",
                f"""\
                schema_version: auditooor.hackerman_record.v1
                record_id: findings-go:solodit-{1000 + i}-cometbft-mixed:abc{i}
                source_audit_ref: findings-go:solodit-{1000 + i}-cometbft-mixed
                target_repo: cometbft/cometbft
                attack_class: ghsa-public-advisory-go
                function_shape:
                  shape_tags:
                    - mixed-shared-tag
                """,
            )
        # ... plus 1 bundle-layout record carrying the same tag.
        _write_record_json(
            bucket / "bundle-1",
            _ghsa_record("bundle-1", "ghsa-public-advisory-go", ["mixed-shared-tag"]),
        )
        rep = self.mod.extract_seeds(self.tags_dir, min_recurrence=3)
        seeds = {r["seed"] for r in rep["regex_seeds"]}
        self.assertIn("mixed-shared-tag", seeds)
        seed_row = next(r for r in rep["regex_seeds"] if r["seed"] == "mixed-shared-tag")
        # 2 flat + 1 bundle = recurrence 3
        self.assertEqual(seed_row["recurrence_count"], 3)
        self.assertEqual(rep["stats"]["real_source_records"], 3)

    def test_flat_quarantine_bucket_still_skipped(self) -> None:
        """Flat-file walk must NOT break the quarantine-bucket exclusion."""
        bucket = self.tags_dir / "_QUARANTINE_FABRICATED_CVE"
        self._write_flat_yaml(
            bucket,
            "fake-flat",
            """\
            schema_version: auditooor.hackerman_record.v1
            record_id: cve_db:cve-2099-0001
            source_audit_ref: https://nvd.nist.gov/cve-2099-0001
            attack_class: fabricated
            function_shape:
              shape_tags:
                - flat-poison-tag
            """,
        )
        real_bucket = self.tags_dir / "cosmos_sdk_ibc"
        for i in range(3):
            self._write_flat_yaml(
                real_bucket,
                f"real-flat-{i}",
                f"""\
                schema_version: auditooor.hackerman_record.v1
                record_id: findings-go:solodit-{2000 + i}-ok:abc{i}
                source_audit_ref: findings-go:solodit-{2000 + i}-ok
                attack_class: ghsa-public-advisory-go
                function_shape:
                  shape_tags:
                    - flat-valid-tag
                """,
            )
        rep = self.mod.extract_seeds(self.tags_dir, min_recurrence=3)
        seeds = {r["seed"] for r in rep["regex_seeds"]}
        self.assertIn("flat-valid-tag", seeds)
        self.assertNotIn("flat-poison-tag", seeds)

    def test_yaml_record_is_parsed_when_json_missing(self) -> None:
        bucket = self.tags_dir / "cosmos_sdk_ibc"
        slug = bucket / "yaml-only"
        slug.mkdir(parents=True)
        (slug / "record.yaml").write_text(
            textwrap.dedent(
                """\
                schema_version: auditooor.hackerman_record.v1
                record_id: cosmos-sdk-ibc:cometbft:ghsa-yaml-only:abc
                source_audit_ref: https://github.com/cometbft/cometbft/security/advisories/GHSA-yaml-only
                target_repo: cometbft/cometbft
                target_language: go
                attack_class: ghsa-public-advisory-go
                source_extraction_method: corpus-etl
                function_shape:
                  raw_signature: github.com/cometbft/cometbft
                  shape_tags:
                    - yaml-shared-tag
                    - another-yaml-tag
                """
            ),
            encoding="utf-8",
        )
        # Plus two more JSON records carrying the same shared tag to satisfy
        # the min-recurrence threshold of 3.
        _write_record_json(
            bucket / "j1",
            _ghsa_record("j1", "ghsa-public-advisory-go", ["yaml-shared-tag"]),
        )
        _write_record_json(
            bucket / "j2",
            _ghsa_record("j2", "ghsa-public-advisory-go", ["yaml-shared-tag"]),
        )
        rep = self.mod.extract_seeds(self.tags_dir, min_recurrence=3)
        seeds = {r["seed"] for r in rep["regex_seeds"]}
        self.assertIn("yaml-shared-tag", seeds)


if __name__ == "__main__":
    unittest.main()
