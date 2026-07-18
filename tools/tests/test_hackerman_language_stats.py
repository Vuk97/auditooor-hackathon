"""Tests for ``tools/hackerman-language-stats.py``.

Wave-1 hackerman capability lift (PR #726). The tool walks
``audit/corpus_tags/tags/**/record.{yaml,json}`` plus flat
``audit/corpus_tags/tags/*.yaml`` files and emits per-target-language
distribution stats (totals, by-tier, by-subtree, top-N).

Cases (>=8):

1. empty tags-dir -> total_records=0, no languages, render_human survives
2. single subdir record -> one language with count=1, correct subtree
3. multi-record records aggregate per language across tiers + subtrees
4. ``<unknown>`` sentinel used when ``target_language`` is missing
5. alias normalisation: ``typescript``->``ts``, ``golang``->``go``,
   ``Solidity-YUL``->``solidity``, ``Py``->``python``
6. record.yaml wins over record.json in the same dir (precedence)
7. flat solodit-spec / dsl_pattern / prior-audit / corpus-mined / seed /
   other tags bucket into ``_flat_*`` subtrees by filename prefix
8. JSON envelope schema is ``auditooor.hackerman_language_stats.v1``
9. deterministic language ordering: by (-total, name)
10. ``top_n_for_language(axis='tier')`` returns top-3 sorted by
    (-count, name); unknown axis raises ValueError
11. CLI default human render exit-code 0 on a populated synthetic corpus
12. CLI ``--json`` emits valid JSON envelope on stdout
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-language-stats.py"


def _load_tool() -> Any:
    name = "_hackerman_language_stats_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_subdir_record(
    tags_dir: Path,
    subtree: str,
    record_id: str,
    *,
    target_language: str | None = None,
    record_tier: str | None = None,
    fmt: str = "yaml",
) -> Path:
    rec_dir = tags_dir / subtree / record_id
    rec_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "yaml":
        lines = [
            "schema_version: auditooor.hackerman_record.v1",
            f"record_id: {record_id}",
            "target_repo: synthetic/test",
        ]
        if target_language is not None:
            lines.append(f"target_language: {target_language}")
        if record_tier is not None:
            lines.append(f"record_tier: {record_tier}")
        path = rec_dir / "record.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path
    obj: dict[str, Any] = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "target_repo": "synthetic/test",
    }
    if target_language is not None:
        obj["target_language"] = target_language
    if record_tier is not None:
        obj["record_tier"] = record_tier
    path = rec_dir / "record.json"
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def _write_flat(
    tags_dir: Path,
    filename: str,
    *,
    target_language: str | None,
    record_tier: str | None = None,
) -> Path:
    lines = ["schema_version: auditooor.hackerman_record.v1"]
    if target_language is not None:
        lines.append(f"target_language: {target_language}")
    if record_tier is not None:
        lines.append(f"record_tier: {record_tier}")
    path = tags_dir / filename
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class HackermanLanguageStatsTests(unittest.TestCase):
    def test_01_empty_tags_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 0)
            self.assertEqual(stats["languages"], [])
            self.assertEqual(stats["language_totals"], {})
            # render_human must not crash on empty corpus
            human = tool.render_human(stats)
            self.assertIn("total_records: 0", human)

    def test_02_single_subdir_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags,
                "lending_protocols",
                "rec_a",
                target_language="solidity",
                record_tier="public-corpus",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["languages"], ["solidity"])
            self.assertEqual(stats["language_totals"]["solidity"], 1)
            self.assertEqual(
                stats["language_by_subtree"]["solidity"]["lending_protocols"],
                1,
            )
            self.assertEqual(
                stats["language_by_tier"]["solidity"]["public-corpus"],
                1,
            )

    def test_03_multi_record_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                target_language="solidity", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "lending_protocols", "r2",
                target_language="solidity", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "cosmos_sdk_ibc", "r3",
                target_language="go", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "substrate_fix_history", "r4",
                target_language="rust", record_tier="local-workspace",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 4)
            self.assertEqual(stats["language_totals"]["solidity"], 2)
            self.assertEqual(stats["language_totals"]["go"], 1)
            self.assertEqual(stats["language_totals"]["rust"], 1)
            self.assertEqual(
                stats["language_by_tier"]["rust"]["local-workspace"], 1
            )
            self.assertEqual(stats["subtree_totals"]["lending_protocols"], 2)

    def test_04_unknown_sentinel_for_missing_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r_no_lang",
                target_language=None, record_tier="public-corpus",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertIn(tool.MISSING_LANG, stats["language_totals"])
            self.assertEqual(stats["language_totals"][tool.MISSING_LANG], 1)

    def test_05_alias_normalisation(self) -> None:
        # via _normalize_language
        cases = [
            ("typescript", "ts"),
            ("Golang", "go"),
            ("Solidity-YUL", "solidity"),
            ("Py", "python"),
            ("  ", tool.MISSING_LANG),
            ("", tool.MISSING_LANG),
            (None, tool.MISSING_LANG),
            (42, tool.MISSING_LANG),
            ("Rust", "rust"),
        ]
        for raw, expected in cases:
            self.assertEqual(
                tool._normalize_language(raw),
                expected,
                msg=f"normalize({raw!r}) expected {expected!r}",
            )

    def test_06_yaml_wins_over_json_in_same_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "rec_both",
                target_language="solidity", record_tier="public-corpus",
                fmt="yaml",
            )
            _write_subdir_record(
                tags, "lending_protocols", "rec_both",
                target_language="go", record_tier="public-corpus",
                fmt="json",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["language_totals"].get("solidity"), 1)
            self.assertNotIn("go", stats["language_totals"])

    def test_07_flat_prefix_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_flat(
                tags, "solodit-spec:foo-1.yaml",
                target_language="solidity",
                record_tier="public-corpus",
            )
            _write_flat(
                tags, "dsl_pattern_foo.yaml",
                target_language="solidity",
            )
            _write_flat(
                tags, "prior-audit-foo.yaml",
                target_language="go",
                record_tier="local-workspace",
            )
            _write_flat(
                tags, "corpus-mined-foo.yaml",
                target_language="rust",
            )
            _write_flat(
                tags, "seed_foo.yaml",
                target_language="vyper",
            )
            _write_flat(
                tags, "miscellaneous_thing.yaml",
                target_language="cairo",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 6)
            buckets = stats["subtree_totals"]
            self.assertEqual(buckets["_flat_solodit_spec"], 1)
            self.assertEqual(buckets["_flat_dsl_pattern"], 1)
            self.assertEqual(buckets["_flat_prior_audit"], 1)
            self.assertEqual(buckets["_flat_corpus_mined"], 1)
            self.assertEqual(buckets["_flat_seed"], 1)
            self.assertEqual(buckets["_flat_other"], 1)
            self.assertEqual(
                stats["language_by_subtree"]["cairo"]["_flat_other"], 1
            )

    def test_08_json_envelope_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                target_language="solidity", record_tier="public-corpus",
            )
            stats = tool.build_stats(tags)
            payload = json.loads(tool.render_json(stats))
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_language_stats.v1",
            )
            self.assertEqual(payload["total_records"], 1)
            self.assertIn("language_totals", payload)
            self.assertIn("language_by_tier", payload)
            self.assertIn("language_by_subtree", payload)
            self.assertIn("top_tiers_per_language", payload)
            self.assertIn("top_subtrees_per_language", payload)

    def test_09_deterministic_language_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # 3 solidity, 2 go, 2 rust -> solidity then (go, rust) by name
            for i in range(3):
                _write_subdir_record(
                    tags, "lending_protocols", f"s{i}",
                    target_language="solidity",
                )
            for i in range(2):
                _write_subdir_record(
                    tags, "cosmos_sdk_ibc", f"g{i}",
                    target_language="go",
                )
            for i in range(2):
                _write_subdir_record(
                    tags, "substrate_fix_history", f"r{i}",
                    target_language="rust",
                )
            stats = tool.build_stats(tags)
            self.assertEqual(
                stats["languages"][:3], ["solidity", "go", "rust"]
            )

    def test_10_top_n_for_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                target_language="solidity", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "lending_protocols", "r2",
                target_language="solidity", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "dex_fix_history", "r3",
                target_language="solidity", record_tier="local-workspace",
            )
            stats = tool.build_stats(tags)
            tiers = tool.top_n_for_language(stats, "tier", "solidity", n=3)
            self.assertEqual(tiers[0]["tier"], "public-corpus")
            self.assertEqual(tiers[0]["count"], 2)
            subs = tool.top_n_for_language(
                stats, "subtree", "solidity", n=3
            )
            # lending_protocols (2) before dex_fix_history (1)
            self.assertEqual(subs[0]["subtree"], "lending_protocols")
            self.assertEqual(subs[0]["count"], 2)
            with self.assertRaises(ValueError):
                tool.top_n_for_language(stats, "bogus", "solidity")

    def test_11_cli_human_exit_code_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                target_language="solidity", record_tier="public-corpus",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("Hackerman language distribution", result.stdout)
            self.assertIn("solidity", result.stdout)

    def test_12_cli_json_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                target_language="solidity", record_tier="public-corpus",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags),
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_language_stats.v1",
            )
            self.assertEqual(payload["total_records"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
