"""Tests for tools/wave2-w25-tier3-promotion-verify.py.

Synthetic fixtures only. Every YAML written here carries the
``synthetic_fixture: true`` marker per real-source-only discipline so the
records are unambiguously NOT corpus material.

Tests intentionally bypass the live ``git show`` plumbing by monkey-patching
``git_show_message`` and ``git_show_name_only`` so the verifier can run
against a synthetic on-disk corpus without requiring any git repository
state.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wave2-w25-tier3-promotion-verify.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "wave2_w25_tier3_promotion_verify", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


VERIFIER = _load_module()


SAMPLE_COMMIT_MESSAGE = """W2.3-residual: promote 13 real-archive prefixes tier-3 to tier-2 (2098 records)

Wave-2 PR #728 residual cleanup of stratifier prefix table.

Added to TIER2_PREFIXES with per-prefix rationale comments:

  zk-auditor:            401 records  (asymmetric-research / trail-of-bits)
  mev-flashloan:         393 records  (canonical flash-loan attack classes)
  mev-exploits:          274 records  (flashbots / blocknative / eigenphi)
                       -------------
  total:                1068 records
"""

SAMPLE_COMMIT_MESSAGE_FULL = """W2.3-residual: promote 13 real-archive prefixes tier-3 to tier-2 (2098 records)

  zk-auditor:            401 records  (a)
  mev-flashloan:         393 records  (b)
  mev-exploits:          274 records  (c)
  zkbugs:                256 records  (d)
  l2-zkrollup:           216 records  (e)
  zk-contest:            173 records  (f)
  zkbugs-catalog:        104 records  (g)
  starknet-cairo-corpus:  75 records  (h)
  zkbugtracker:           54 records  (i)
  bridge-incident:        48 records  (j)
  solana-svm:             32 records  (k)
  movebit:                29 records  (l)
  vyper-39363:            27 records  (m)
  cve-db:                 16 records  (n)
                       -------------
  total:                2098 records
"""


def _write_yaml_record(
    root: Path,
    rel_dir: str,
    record_id: str,
    tier_shape_tag: str = "tier-2-verified-public-archive",
    top_level_tier: str | None = None,
    fmt: str = "yaml",
) -> Path:
    """Write a synthetic record YAML or JSON file."""
    d = root / rel_dir
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"record.{fmt}"
    if fmt == "yaml":
        lines = [
            "schema_version: auditooor.hackerman_record.v1",
            "synthetic_fixture: true",
            f"record_id: {record_id}",
        ]
        if top_level_tier is not None:
            lines.append(f"verification_tier: {top_level_tier}")
        lines += [
            "function_shape:",
            "  raw_signature: synth",
            "  shape_tags:",
            "    - solidity",
            f"    - verification_tier:{tier_shape_tag}",
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    elif fmt == "json":
        obj = {
            "schema_version": "auditooor.hackerman_record.v1",
            "synthetic_fixture": True,
            "record_id": record_id,
            "function_shape": {
                "raw_signature": "synth",
                "shape_tags": [
                    "solidity",
                    f"verification_tier:{tier_shape_tag}",
                ],
            },
        }
        if top_level_tier is not None:
            obj["verification_tier"] = top_level_tier
        path.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    return path


def _write_index(root: Path, rows: List[dict]) -> Path:
    """Write a synthetic by_verification_tier.jsonl index."""
    idx_dir = root / "audit" / "corpus_tags" / "index"
    idx_dir.mkdir(parents=True, exist_ok=True)
    p = idx_dir / "by_verification_tier.jsonl"
    with p.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    return p


class ParseExpectedBreakdownTests(unittest.TestCase):
    def test_parses_three_prefix_rows_plus_total(self):
        per_prefix, total = VERIFIER.parse_expected_breakdown(SAMPLE_COMMIT_MESSAGE)
        self.assertEqual(
            per_prefix,
            {"zk-auditor": 401, "mev-flashloan": 393, "mev-exploits": 274},
        )
        self.assertEqual(total, 1068)

    def test_parses_full_thirteen_prefix_rows(self):
        per_prefix, total = VERIFIER.parse_expected_breakdown(
            SAMPLE_COMMIT_MESSAGE_FULL
        )
        self.assertEqual(len(per_prefix), 14)
        self.assertEqual(sum(per_prefix.values()), 2098)
        self.assertEqual(total, 2098)

    def test_empty_message_yields_empty_mapping(self):
        per_prefix, total = VERIFIER.parse_expected_breakdown(
            "no rows here, only prose."
        )
        self.assertEqual(per_prefix, {})
        self.assertIsNone(total)


class VerifyFlowTests(unittest.TestCase):
    """Drive the full verify() flow against a synthetic corpus.

    We monkey-patch ``git_show_message`` and ``git_show_name_only`` on the
    loaded module so no real git plumbing is invoked.
    """

    def setUp(self):
        self._orig_git_show_message = VERIFIER.git_show_message
        self._orig_git_show_name_only = VERIFIER.git_show_name_only

    def tearDown(self):
        VERIFIER.git_show_message = self._orig_git_show_message
        VERIFIER.git_show_name_only = self._orig_git_show_name_only

    def _make_corpus(self, root: Path, records: list, with_index: bool = True):
        """Each record is a tuple (rel_dir, record_id, shape_tier).

        Returns the list of relative paths suitable for monkey-patching
        ``git_show_name_only``.
        """
        rel_paths: List[str] = []
        for rel_dir, record_id, shape_tier in records:
            p = _write_yaml_record(
                root, rel_dir, record_id, tier_shape_tag=shape_tier
            )
            rel_paths.append(str(p.relative_to(root)))
        if with_index:
            idx_rows = []
            for rel_dir, record_id, shape_tier in records:
                idx_rows.append(
                    {
                        "key": f"tier-2-verified-public-archive"
                        if shape_tier == "tier-2-verified-public-archive"
                        else shape_tier,
                        "record_id": record_id,
                        "tag_file": "record.yaml",
                    }
                )
            _write_index(root, idx_rows)
        return rel_paths

    def test_pass_synthetic_full_match(self):
        """Synthetic corpus where every record at expected prefix is tier-2."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            records = [
                (
                    f"audit/corpus_tags/tags/zk_miners/zkaud{i}",
                    f"zk-auditor:repo-{i}:hash{i}",
                    "tier-2-verified-public-archive",
                )
                for i in range(3)
            ] + [
                (
                    f"audit/corpus_tags/tags/mev_flashloan/mev{i}",
                    f"mev-flashloan:case-{i}:hash{i}",
                    "tier-2-verified-public-archive",
                )
                for i in range(2)
            ] + [
                (
                    f"audit/corpus_tags/tags/mev_exploits/mevx{i}",
                    f"mev-exploits:flash-{i}:hash{i}",
                    "tier-2-verified-public-archive",
                )
                for i in range(1)
            ]
            rel_paths = self._make_corpus(root, records)

            message = (
                "synthetic_fixture: true\n\n"
                "  zk-auditor:            3 records (synthetic)\n"
                "  mev-flashloan:         2 records (synthetic)\n"
                "  mev-exploits:          1 records (synthetic)\n"
                "                      -------------\n"
                "  total:                 6 records\n"
            )

            VERIFIER.git_show_message = lambda sha, ws: message
            VERIFIER.git_show_name_only = lambda sha, ws: rel_paths

            result = VERIFIER.verify(workspace=root, commit_sha="synthetic")
            self.assertEqual(
                result["overall_status"], "PASS", msg=result.get("discrepancies")
            )
            self.assertEqual(result["total_files_modified"], 6)
            self.assertEqual(result["total_records_at_tier_2"], 6)
            self.assertEqual(
                result["top_3_verification"]["zk-auditor"]["status"], "PASS"
            )

    def test_fail_mismatch_count(self):
        """Synthetic corpus with one fewer record than expected -> FAIL."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            records = [
                (
                    f"audit/corpus_tags/tags/zk_miners/zkaud{i}",
                    f"zk-auditor:repo-{i}:hash{i}",
                    "tier-2-verified-public-archive",
                )
                for i in range(2)  # only 2 written
            ]
            rel_paths = self._make_corpus(root, records)

            message = (
                "synthetic_fixture: true\n\n"
                "  zk-auditor:            3 records (synthetic)\n"
                "                      -------------\n"
                "  total:                 3 records\n"
            )

            VERIFIER.git_show_message = lambda sha, ws: message
            VERIFIER.git_show_name_only = lambda sha, ws: rel_paths

            result = VERIFIER.verify(workspace=root, commit_sha="synthetic")
            self.assertEqual(result["overall_status"], "FAIL")
            self.assertEqual(
                result["prefix_breakdown"]["zk-auditor"]["delta"], -1
            )
            self.assertTrue(
                any("zk-auditor" in d for d in result["discrepancies"])
            )

    def test_fail_missing_prefix(self):
        """Synthetic corpus where mev-flashloan has zero tier-2 records."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # All zk-auditor records present, but mev-flashloan completely absent.
            records = [
                (
                    f"audit/corpus_tags/tags/zk_miners/zkaud{i}",
                    f"zk-auditor:repo-{i}:hash{i}",
                    "tier-2-verified-public-archive",
                )
                for i in range(3)
            ]
            rel_paths = self._make_corpus(root, records)

            message = (
                "synthetic_fixture: true\n\n"
                "  zk-auditor:            3 records (synthetic)\n"
                "  mev-flashloan:         2 records (synthetic)\n"
                "                      -------------\n"
                "  total:                 5 records\n"
            )

            VERIFIER.git_show_message = lambda sha, ws: message
            VERIFIER.git_show_name_only = lambda sha, ws: rel_paths

            result = VERIFIER.verify(workspace=root, commit_sha="synthetic")
            self.assertEqual(result["overall_status"], "FAIL")
            self.assertEqual(
                result["top_3_verification"]["mev-flashloan"]["status"], "FAIL"
            )
            self.assertEqual(
                result["prefix_breakdown"]["mev-flashloan"]["actual"], 0
            )

    def test_warning_index_inconsistency(self):
        """Corpus is at tier-2 but the index undercounts -> WARNING."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            records = [
                (
                    f"audit/corpus_tags/tags/zk_miners/zkaud{i}",
                    f"zk-auditor:repo-{i}:hash{i}",
                    "tier-2-verified-public-archive",
                )
                for i in range(3)
            ] + [
                (
                    f"audit/corpus_tags/tags/mev_flashloan/mev{i}",
                    f"mev-flashloan:case-{i}:hash{i}",
                    "tier-2-verified-public-archive",
                )
                for i in range(2)
            ] + [
                (
                    f"audit/corpus_tags/tags/mev_exploits/mevx{i}",
                    f"mev-exploits:flash-{i}:hash{i}",
                    "tier-2-verified-public-archive",
                )
                for i in range(1)
            ]
            rel_paths = self._make_corpus(root, records, with_index=False)
            # Now write an index that intentionally undercounts zk-auditor by 1.
            idx_rows = []
            for rel_dir, record_id, shape_tier in records[1:]:  # skip first
                idx_rows.append(
                    {
                        "key": "tier-2-verified-public-archive",
                        "record_id": record_id,
                        "tag_file": "record.yaml",
                    }
                )
            _write_index(root, idx_rows)

            message = (
                "synthetic_fixture: true\n\n"
                "  zk-auditor:            3 records (synthetic)\n"
                "  mev-flashloan:         2 records (synthetic)\n"
                "  mev-exploits:          1 records (synthetic)\n"
                "                      -------------\n"
                "  total:                 6 records\n"
            )

            VERIFIER.git_show_message = lambda sha, ws: message
            VERIFIER.git_show_name_only = lambda sha, ws: rel_paths

            result = VERIFIER.verify(workspace=root, commit_sha="synthetic")
            # Corpus is at expected tier-2 but index undercounts -> WARNING.
            self.assertEqual(result["overall_status"], "WARNING")
            self.assertIn(
                "zk-auditor",
                result["index_cross_check"]["per_prefix_consistency"],
            )
            cc = result["index_cross_check"]["per_prefix_consistency"][
                "zk-auditor"
            ]
            self.assertEqual(cc["corpus"], 3)
            self.assertEqual(cc["index"], 2)


class TopLevelVerificationTierFieldTests(unittest.TestCase):
    """v1.1 top-level ``verification_tier`` should override the legacy
    shape_tags signal when present."""

    def test_top_level_field_wins(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = _write_yaml_record(
                root,
                "audit/corpus_tags/tags/zk_miners/zkaud0",
                "zk-auditor:repo-0:hash0",
                tier_shape_tag="tier-3-synthetic-taxonomy-anchored",
                top_level_tier="tier-2-verified-public-archive",
            )
            rec = VERIFIER.parse_record(p)
            self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
            self.assertEqual(rec["shape_tag_tier"], "tier-3-synthetic-taxonomy-anchored")
            self.assertEqual(
                VERIFIER.effective_tier(rec), "tier-2-verified-public-archive"
            )


if __name__ == "__main__":
    unittest.main()
