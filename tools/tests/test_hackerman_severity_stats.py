"""Tests for ``tools/hackerman-severity-stats.py``.

Wave-1 hackerman capability lift (PR #726). The tool walks
``audit/corpus_tags/tags/**/record.{yaml,json}`` plus flat
``audit/corpus_tags/tags/*.yaml`` files and emits per-severity
distribution stats (totals, by-tier, by-subtree, top-N).

Cases (>=8):

1.  empty tags-dir -> total_records=0, no severities, render_human
    survives.
2.  single subdir record -> one severity with count=1, correct subtree
    and tier.
3.  multi-record records aggregate per severity across tiers + subtrees.
4.  ``<unknown>`` sentinel used when ``severity_at_finding`` is missing.
5.  alias normalisation: ``Crit``->``critical``, ``Med``->``medium``,
    ``Informational``->``info``, ``None``->``info``, whitespace/non-string
    -> sentinel.
6.  record.yaml wins over record.json in the same dir (precedence).
7.  flat solodit-spec / dsl_pattern / prior-audit / corpus-mined / seed /
    other tags bucket into ``_flat_*`` subtrees by filename prefix.
8.  JSON envelope schema is ``auditooor.hackerman_severity_stats.v1``.
9.  canonical severity ordering: critical, high, medium, low, info,
    then any non-canonical alphabetical after.
10. ``top_n_for_severity(axis='tier')`` returns top-3 sorted by
    (-count, name); unknown axis raises ValueError.
11. CLI default human render exit-code 0 on a populated synthetic corpus.
12. CLI ``--json`` emits valid JSON envelope on stdout.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-severity-stats.py"


def _load_tool() -> Any:
    name = "_hackerman_severity_stats_test_mod"
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
    severity_at_finding: str | None = None,
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
        if severity_at_finding is not None:
            lines.append(f"severity_at_finding: {severity_at_finding}")
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
    if severity_at_finding is not None:
        obj["severity_at_finding"] = severity_at_finding
    if record_tier is not None:
        obj["record_tier"] = record_tier
    path = rec_dir / "record.json"
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def _write_flat(
    tags_dir: Path,
    filename: str,
    *,
    severity_at_finding: str | None,
    record_tier: str | None = None,
) -> Path:
    lines = ["schema_version: auditooor.hackerman_record.v1"]
    if severity_at_finding is not None:
        lines.append(f"severity_at_finding: {severity_at_finding}")
    if record_tier is not None:
        lines.append(f"record_tier: {record_tier}")
    path = tags_dir / filename
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class HackermanSeverityStatsTests(unittest.TestCase):
    def test_01_empty_tags_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 0)
            self.assertEqual(stats["severities"], [])
            self.assertEqual(stats["severity_totals"], {})
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
                severity_at_finding="critical",
                record_tier="public-corpus",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["severities"], ["critical"])
            self.assertEqual(stats["severity_totals"]["critical"], 1)
            self.assertEqual(
                stats["severity_by_subtree"]["critical"]["lending_protocols"],
                1,
            )
            self.assertEqual(
                stats["severity_by_tier"]["critical"]["public-corpus"],
                1,
            )

    def test_03_multi_record_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                severity_at_finding="critical", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "lending_protocols", "r2",
                severity_at_finding="critical", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "lending_protocols", "r3",
                severity_at_finding="high", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "cosmos_sdk_ibc", "r4",
                severity_at_finding="medium", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "substrate_fix_history", "r5",
                severity_at_finding="low", record_tier="local-workspace",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 5)
            self.assertEqual(stats["severity_totals"]["critical"], 2)
            self.assertEqual(stats["severity_totals"]["high"], 1)
            self.assertEqual(stats["severity_totals"]["medium"], 1)
            self.assertEqual(stats["severity_totals"]["low"], 1)
            self.assertEqual(
                stats["severity_by_tier"]["low"]["local-workspace"], 1
            )
            self.assertEqual(stats["subtree_totals"]["lending_protocols"], 3)

    def test_04_unknown_sentinel_for_missing_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r_no_sev",
                severity_at_finding=None, record_tier="public-corpus",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertIn(tool.MISSING_SEVERITY, stats["severity_totals"])
            self.assertEqual(
                stats["severity_totals"][tool.MISSING_SEVERITY], 1
            )

    def test_05_alias_normalisation(self) -> None:
        cases = [
            ("Crit", "critical"),
            ("CRITICAL", "critical"),
            ("hi", "high"),
            ("High", "high"),
            ("Med", "medium"),
            ("MODERATE", "medium"),
            ("Informational", "info"),
            ("note", "info"),
            ("Gas", "info"),
            ("None", "info"),
            ("n/a", "info"),
            ("  ", tool.MISSING_SEVERITY),
            ("", tool.MISSING_SEVERITY),
            (None, tool.MISSING_SEVERITY),
            (42, tool.MISSING_SEVERITY),
            ("low", "low"),
        ]
        for raw, expected in cases:
            self.assertEqual(
                tool._normalize_severity(raw),
                expected,
                msg=f"normalize({raw!r}) expected {expected!r}",
            )

    def test_06_yaml_wins_over_json_in_same_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "rec_both",
                severity_at_finding="critical", record_tier="public-corpus",
                fmt="yaml",
            )
            _write_subdir_record(
                tags, "lending_protocols", "rec_both",
                severity_at_finding="low", record_tier="public-corpus",
                fmt="json",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["severity_totals"].get("critical"), 1)
            self.assertNotIn("low", stats["severity_totals"])

    def test_07_flat_prefix_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_flat(
                tags, "solodit-spec:foo-1.yaml",
                severity_at_finding="critical",
                record_tier="public-corpus",
            )
            _write_flat(
                tags, "dsl_pattern_foo.yaml",
                severity_at_finding="high",
            )
            _write_flat(
                tags, "prior-audit-foo.yaml",
                severity_at_finding="medium",
                record_tier="local-workspace",
            )
            _write_flat(
                tags, "corpus-mined-foo.yaml",
                severity_at_finding="low",
            )
            _write_flat(
                tags, "seed_foo.yaml",
                severity_at_finding="info",
            )
            _write_flat(
                tags, "miscellaneous_thing.yaml",
                severity_at_finding="high",
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
                stats["severity_by_subtree"]["high"]["_flat_dsl_pattern"], 1
            )

    def test_08_json_envelope_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                severity_at_finding="critical", record_tier="public-corpus",
            )
            stats = tool.build_stats(tags)
            payload = json.loads(tool.render_json(stats))
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_severity_stats.v1",
            )
            self.assertEqual(payload["total_records"], 1)
            self.assertIn("severity_totals", payload)
            self.assertIn("severity_by_tier", payload)
            self.assertIn("severity_by_subtree", payload)
            self.assertIn("top_tiers_per_severity", payload)
            self.assertIn("top_subtrees_per_severity", payload)

    def test_09_canonical_severity_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # Insert in non-canonical order: low, critical, medium, high,
            # info, plus a non-canonical "weird" severity that should
            # appear AFTER the 5 canonical rows alphabetically.
            for i, sev in enumerate([
                "low", "critical", "medium", "high", "info", "weird",
            ]):
                _write_subdir_record(
                    tags, "lending_protocols", f"r{i}",
                    severity_at_finding=sev,
                )
            stats = tool.build_stats(tags)
            self.assertEqual(
                stats["severities"][:5],
                ["critical", "high", "medium", "low", "info"],
            )
            # "weird" must be after canonical rows
            self.assertEqual(stats["severities"][5], "weird")

    def test_10_top_n_for_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                severity_at_finding="critical", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "lending_protocols", "r2",
                severity_at_finding="critical", record_tier="public-corpus",
            )
            _write_subdir_record(
                tags, "dex_fix_history", "r3",
                severity_at_finding="critical", record_tier="local-workspace",
            )
            stats = tool.build_stats(tags)
            tiers = tool.top_n_for_severity(stats, "tier", "critical", n=3)
            self.assertEqual(tiers[0]["tier"], "public-corpus")
            self.assertEqual(tiers[0]["count"], 2)
            subs = tool.top_n_for_severity(
                stats, "subtree", "critical", n=3
            )
            # lending_protocols (2) before dex_fix_history (1)
            self.assertEqual(subs[0]["subtree"], "lending_protocols")
            self.assertEqual(subs[0]["count"], 2)
            with self.assertRaises(ValueError):
                tool.top_n_for_severity(stats, "bogus", "critical")

    def test_11_cli_human_exit_code_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                severity_at_finding="critical", record_tier="public-corpus",
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
            self.assertIn("Hackerman severity distribution", result.stdout)
            self.assertIn("critical", result.stdout)

    def test_12_cli_json_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                severity_at_finding="critical", record_tier="public-corpus",
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
                "auditooor.hackerman_severity_stats.v1",
            )
            self.assertEqual(payload["total_records"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
