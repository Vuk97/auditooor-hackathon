"""Tests for ``tools/hackerman-year-stats.py``.

Wave-1 hackerman capability lift (PR #726). The tool walks
``audit/corpus_tags/tags/**/record.{yaml,json}`` plus flat
``audit/corpus_tags/tags/*.yaml`` files and emits per-year
distribution stats (totals, chronological, tier-1/2/3 breakdown,
subtree breakdown).

Cases (>=8):

1.  empty tags-dir -> total_records=0, no years, render_human survives.
2.  single subdir record with top-level ``year:`` -> one year with
    count=1, correct subtree, tier extracted.
3.  multi-record aggregation across multiple years, sorted
    chronologically.
4.  year extracted from ``incident_date`` (YYYY-MM-DD) when top-level
    ``year`` is absent.
5.  year extracted from ``disclosure_date`` ISO timestamp.
6.  ``Published-at YYYY-...`` precondition substring extraction.
7.  year extracted from ``source_audit_ref`` URL regex (20\\d{2}).
8.  ``<missing-year>`` sentinel when no year can be extracted.
9.  ``year_by_tier`` breakdown with tier-1 / tier-2 / tier-3
    normalisation.
10. record.yaml wins over record.json in the same dir (precedence).
11. flat tag filename buckets into ``_flat_*`` subtrees.
12. JSON envelope schema is ``auditooor.hackerman_year_stats.v1`` and
    carries ``top_years`` + per-year tier cells.
13. CLI default human render exit-code 0 on a populated synthetic corpus.
14. CLI ``--json`` emits valid JSON envelope on stdout.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-year-stats.py"


def _load_tool() -> Any:
    name = "_hackerman_year_stats_test_mod"
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
    target_repo: str | None = "synthetic/test",
    year: Any = None,
    incident_date: str | None = None,
    disclosure_date: str | None = None,
    source_audit_ref: str | None = None,
    verification_tier_tag: str | None = None,
    published_at_precondition: str | None = None,
    fmt: str = "yaml",
) -> Path:
    rec_dir = tags_dir / subtree / record_id
    rec_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "yaml":
        lines = [
            "schema_version: auditooor.hackerman_record.v1",
            f"record_id: {record_id}",
        ]
        if target_repo is not None:
            lines.append(f"target_repo: {target_repo}")
        if year is not None:
            lines.append(f"year: {year}")
        if incident_date is not None:
            lines.append(f"incident_date: {incident_date}")
        if disclosure_date is not None:
            lines.append(f"disclosure_date: {disclosure_date}")
        if source_audit_ref is not None:
            lines.append(f"source_audit_ref: {source_audit_ref}")
        if verification_tier_tag is not None:
            lines.append("function_shape:")
            lines.append("  raw_signature: synthetic-shape")
            lines.append("  shape_tags:")
            lines.append(f"    - {verification_tier_tag}")
        if published_at_precondition is not None:
            lines.append("required_preconditions:")
            lines.append(f"  - \"{published_at_precondition}\"")
        path = rec_dir / "record.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path
    obj: dict[str, Any] = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
    }
    if target_repo is not None:
        obj["target_repo"] = target_repo
    if year is not None:
        obj["year"] = year
    if incident_date is not None:
        obj["incident_date"] = incident_date
    if disclosure_date is not None:
        obj["disclosure_date"] = disclosure_date
    if source_audit_ref is not None:
        obj["source_audit_ref"] = source_audit_ref
    if verification_tier_tag is not None:
        obj["function_shape"] = {
            "raw_signature": "synthetic-shape",
            "shape_tags": [verification_tier_tag],
        }
    if published_at_precondition is not None:
        obj["required_preconditions"] = [published_at_precondition]
    path = rec_dir / "record.json"
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def _write_flat(
    tags_dir: Path,
    filename: str,
    *,
    year: Any | None = None,
    verification_tier_tag: str | None = None,
) -> Path:
    lines = ["schema_version: auditooor.hackerman_record.v1"]
    if year is not None:
        lines.append(f"year: {year}")
    if verification_tier_tag is not None:
        lines.append("function_shape:")
        lines.append("  raw_signature: synthetic-shape")
        lines.append("  shape_tags:")
        lines.append(f"    - {verification_tier_tag}")
    path = tags_dir / filename
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class HackermanYearStatsTests(unittest.TestCase):
    def test_01_empty_tags_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 0)
            self.assertEqual(stats["years"], [])
            self.assertEqual(stats["year_totals"], {})
            # render_human must not crash on empty corpus
            human = tool.render_human(stats)
            self.assertIn("total_records: 0", human)
            self.assertIn("year distribution", human)

    def test_02_single_record_top_level_year(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "rec_a",
                year=2024,
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["years"], ["2024"])
            self.assertEqual(stats["year_totals"]["2024"], 1)
            self.assertEqual(
                stats["year_by_subtree"]["2024"]["lending_protocols"], 1
            )
            self.assertEqual(stats["year_by_tier"]["2024"]["tier-1"], 1)
            self.assertEqual(stats["tier_totals"]["tier-1"], 1)

    def test_03_multi_record_chronological_sort(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            for year, n in [(2021, 1), (2024, 3), (2022, 2), (2023, 4)]:
                for i in range(n):
                    _write_subdir_record(
                        tags, "lending_protocols", f"y{year}_{i}",
                        year=year,
                        verification_tier_tag=(
                            "verification_tier:tier-1-verified-realtime-api"
                        ),
                    )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 10)
            # Years key is chronologically sorted
            self.assertEqual(
                stats["years"],
                ["2021", "2022", "2023", "2024"],
            )
            self.assertEqual(stats["year_totals"]["2021"], 1)
            self.assertEqual(stats["year_totals"]["2022"], 2)
            self.assertEqual(stats["year_totals"]["2023"], 4)
            self.assertEqual(stats["year_totals"]["2024"], 3)
            # top_years() is ranked by count
            top = tool.top_years(stats, 4)
            self.assertEqual([t["year"] for t in top],
                             ["2023", "2024", "2022", "2021"])
            self.assertEqual(top[0]["count"], 4)

    def test_04_incident_date_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r_inc",
                year=None,
                incident_date="2022-09-15",
                verification_tier_tag=(
                    "verification_tier:tier-2-verified-public-archive"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["year_totals"]["2022"], 1)

    def test_05_disclosure_date_iso_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r_disc",
                year=None,
                disclosure_date="2023-06-01T08:56:28Z",
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["year_totals"]["2023"], 1)

    def test_06_published_at_precondition_substring(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r_pub",
                year=None,
                published_at_precondition=(
                    "Published-at 2021-07-09T21:17:04Z"
                ),
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["year_totals"]["2021"], 1)

    def test_07_source_audit_ref_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # No year / incident_date / disclosure_date / preconditions;
            # only the URL carries a year string.
            _write_subdir_record(
                tags, "lending_protocols", "r_url",
                year=None,
                source_audit_ref=(
                    "https://code4rena.com/contests/2020-12-test-contest"
                ),
                verification_tier_tag=(
                    "verification_tier:tier-3-synthetic-taxonomy-anchored"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["year_totals"]["2020"], 1)

    def test_08_missing_year_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # No year / dates / URL with year; only an arbitrary
            # source_audit_ref string with no 20xx hit.
            _write_subdir_record(
                tags, "lending_protocols", "r_none",
                year=None,
                source_audit_ref="https://example.com/no-year-here",
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertIn(tool.MISSING_YEAR, stats["year_totals"])
            self.assertEqual(stats["year_totals"][tool.MISSING_YEAR], 1)
            # Missing bucket sorts after canonical years
            self.assertEqual(stats["years"][-1], tool.MISSING_YEAR)

    def test_09_tier_breakdown_normalisation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # Two tier-1 subtype suffixes -> both collapse to tier-1
            _write_subdir_record(
                tags, "lending_protocols", "r_t1a",
                year=2024,
                verification_tier_tag=(
                    "verification_tier:tier-1-ghsa-rest-api"
                ),
            )
            _write_subdir_record(
                tags, "lending_protocols", "r_t1b",
                year=2024,
                verification_tier_tag=(
                    "verification_tier:tier-1-live-fetch"
                ),
            )
            _write_subdir_record(
                tags, "lending_protocols", "r_t2",
                year=2024,
                verification_tier_tag=(
                    "verification_tier:tier-2-verified-public-archive"
                ),
            )
            _write_subdir_record(
                tags, "lending_protocols", "r_t3",
                year=2024,
                verification_tier_tag=(
                    "verification_tier:tier-3-synthetic-taxonomy-anchored"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["year_by_tier"]["2024"]["tier-1"], 2)
            self.assertEqual(stats["year_by_tier"]["2024"]["tier-2"], 1)
            self.assertEqual(stats["year_by_tier"]["2024"]["tier-3"], 1)

    def test_10_yaml_wins_over_json_in_same_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "rec_both",
                year=2024,
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
                fmt="yaml",
            )
            _write_subdir_record(
                tags, "lending_protocols", "rec_both",
                year=2019,
                verification_tier_tag=(
                    "verification_tier:tier-3-synthetic-taxonomy-anchored"
                ),
                fmt="json",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["year_totals"].get("2024"), 1)
            self.assertNotIn("2019", stats["year_totals"])

    def test_11_flat_prefix_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_flat(
                tags, "solodit-spec:foo-1.yaml", year=2023,
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            _write_flat(tags, "dsl_pattern_foo.yaml", year=2024)
            _write_flat(
                tags, "prior-audit-foo.yaml", year=2022,
                verification_tier_tag=(
                    "verification_tier:tier-2-verified-public-archive"
                ),
            )
            _write_flat(tags, "corpus-mined-foo.yaml", year=2021)
            _write_flat(tags, "seed_foo.yaml", year=2020)
            _write_flat(tags, "miscellaneous_thing.yaml", year=2025)
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 6)
            buckets = stats["subtree_totals"]
            self.assertEqual(buckets["_flat_solodit_spec"], 1)
            self.assertEqual(buckets["_flat_dsl_pattern"], 1)
            self.assertEqual(buckets["_flat_prior_audit"], 1)
            self.assertEqual(buckets["_flat_corpus_mined"], 1)
            self.assertEqual(buckets["_flat_seed"], 1)
            self.assertEqual(buckets["_flat_other"], 1)
            # Spot check a year x subtree cell
            self.assertEqual(
                stats["year_by_subtree"]["2023"]["_flat_solodit_spec"], 1
            )

    def test_12_json_envelope_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                year=2024,
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            stats = tool.build_stats(tags)
            payload = json.loads(tool.render_json(stats))
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_year_stats.v1",
            )
            self.assertEqual(payload["total_records"], 1)
            self.assertIn("year_totals", payload)
            self.assertIn("year_by_tier", payload)
            self.assertIn("year_by_subtree", payload)
            self.assertIn("top_years", payload)
            ty0 = payload["top_years"][0]
            self.assertEqual(ty0["year"], "2024")
            self.assertEqual(ty0["count"], 1)
            self.assertEqual(ty0["tier_1"], 1)
            self.assertEqual(ty0["tier_2"], 0)
            self.assertEqual(ty0["tier_3"], 0)

    def test_13_cli_human_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                year=2024,
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            result = subprocess.run(
                [sys.executable, str(TOOL_PATH), "--tags-dir", str(tags)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("Hackerman year distribution", result.stdout)
            self.assertIn("2024", result.stdout)

    def test_14_cli_json_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                year=2024,
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            result = subprocess.run(
                [sys.executable, str(TOOL_PATH), "--tags-dir", str(tags),
                 "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_year_stats.v1",
            )
            self.assertEqual(payload["total_records"], 1)
            self.assertEqual(payload["top_years"][0]["year"], "2024")
            self.assertEqual(payload["top_years"][0]["tier_1"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
