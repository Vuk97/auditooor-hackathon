"""Tests for ``tools/hackerman-pr726-density-analyzer.py``.

Wave-1 hackerman capability lift (PR #726). The tool reads ``git log``
output for the wave-1-hackerman-capability-lift branch and aggregates
commit cadence, author distribution, lane velocity, and hour-of-day
landing.

Cases (>=8 required by the task brief):

1.  empty log -> total_commits=0, distinct_days=0, render survives.
2.  parse_log: well-formed 5-field lines round-trip; sha, author,
    day (YYYY-MM-DD), hour, and lane fields populated.
3.  parse_log: malformed lines (<5 fields, non-hex sha) are silently
    skipped without raising.
4.  detect_lane: ``W2.1`` / ``Wave-1`` / scope(...) / hackerman-foo /
    PR #726 patterns all classify into stable canonical lanes.
5.  detect_lane: subjects with no recognised pattern fall back to
    ``<other>``.
6.  aggregate: commits_per_day sorted asc by date; top_days sorted
    desc by count with tie-break asc by date.
7.  aggregate: top_authors sorted desc by count, tie-break asc by
    author; cap at TOP_AUTHORS.
8.  aggregate: top_lanes capped at TOP_LANES=5; hour_of_day always
    24 buckets (0..23) regardless of input coverage.
9.  build_envelope: schema string is exactly
    ``auditooor.hackerman_pr726_density_analyzer.v1`` and includes
    branch / since / generated_at / stats / commits_per_day /
    top_days / top_authors / top_lanes / hour_of_day keys.
10. CLI ``--log-file`` reads a synthetic captured log and emits the
    human report (exit 0).
11. CLI ``--log-file --json --generated-at <ts>`` emits a valid JSON
    envelope on stdout with the override timestamp honoured.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-pr726-density-analyzer.py"


def _load_tool() -> Any:
    name = "_hackerman_pr726_density_analyzer_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


# Synthetic fixture lines mimicking the canonical git log format:
# %H|%an|%ae|%ad|%s with --date=iso.
FIXTURE_LINES = [
    "a1b2c3d4e5f6789012345678901234567890abcd|"
    "Alice|alice@example.com|2026-05-10 09:15:00 +0200|"
    "PR #726 wave-1: foo bar",
    "b1b2c3d4e5f6789012345678901234567890abcd|"
    "Bob|bob@example.com|2026-05-10 14:00:00 +0200|"
    "W2.1 schema migration",
    "c1b2c3d4e5f6789012345678901234567890abcd|"
    "Alice|alice@example.com|2026-05-11 03:30:00 +0200|"
    "docs(wave-2): acceptance gate spec",
    "d1b2c3d4e5f6789012345678901234567890abcd|"
    "Bob|bob@example.com|2026-05-12 23:59:00 +0200|"
    "PR #726 wave-1: hackerman-foo-bar helper",
    "e1b2c3d4e5f6789012345678901234567890abcd|"
    "Alice|alice@example.com|2026-05-12 23:59:00 +0200|"
    "miscellaneous cleanup with no lane signal",
]
FIXTURE_LOG = "\n".join(FIXTURE_LINES) + "\n"


class TestParse(unittest.TestCase):
    def test_empty_log_yields_zero_records(self) -> None:
        recs = tool.parse_log("")
        self.assertEqual(recs, [])
        agg = tool.aggregate(recs)
        self.assertEqual(agg["total_commits"], 0)
        self.assertEqual(agg["distinct_days"], 0)
        # render must not raise on empty data.
        text = tool.render_report(agg, generated_at="2026-05-16T00:00:00Z")
        self.assertIn("total_commits: 0", text)

    def test_parse_well_formed_lines(self) -> None:
        recs = tool.parse_log(FIXTURE_LOG)
        self.assertEqual(len(recs), 5)
        first = recs[0]
        self.assertEqual(first["sha"][:8], "a1b2c3d4")
        self.assertEqual(first["author_name"], "Alice")
        self.assertEqual(first["day"], "2026-05-10")
        self.assertEqual(first["hour"], 9)
        # PR #726 should resolve to pr-726 lane (first matching pattern is wave-1 -> "wave-1")
        self.assertIn(first["lane"], {"wave-1", "pr-726"})

    def test_parse_skips_malformed_lines(self) -> None:
        bad = "\n".join(
            [
                "not-a-real-line",  # no pipes
                "shortsha|Alice|a@b.com|2026-05-10 09:00:00|subj",  # sha not hex
                "abc|too|few|fields",  # only 4 fields
                "",  # blank
                FIXTURE_LINES[0],  # one valid
            ]
        )
        recs = tool.parse_log(bad)
        self.assertEqual(len(recs), 1)


class TestLaneDetection(unittest.TestCase):
    def test_lane_patterns(self) -> None:
        self.assertEqual(tool.detect_lane("W2.1 schema migration"), "W2.1")
        self.assertEqual(
            tool.detect_lane("docs(wave-2): acceptance gate"), "wave-2"
        )
        self.assertEqual(
            tool.detect_lane("PR #726 wave-1: foo bar"), "wave-1"
        )
        # hackerman-<slug> only fires if no wave / scope / PR matches first.
        self.assertEqual(
            tool.detect_lane("add hackerman-foo-bar helper"),
            "hackerman-foo-bar",
        )

    def test_lane_fallback(self) -> None:
        self.assertEqual(
            tool.detect_lane("miscellaneous cleanup with no lane signal"),
            "<other>",
        )


class TestAggregate(unittest.TestCase):
    def test_commits_per_day_sorted_asc(self) -> None:
        recs = tool.parse_log(FIXTURE_LOG)
        agg = tool.aggregate(recs)
        days = [item["day"] for item in agg["commits_per_day"]]
        self.assertEqual(days, sorted(days))
        # 2026-05-10 has 2 commits, 2026-05-12 has 2 commits -> top_days
        # tie-break asc by date means 2026-05-10 < 2026-05-12.
        top = agg["top_days"]
        self.assertEqual(top[0]["count"], top[1]["count"])
        self.assertLess(top[0]["day"], top[1]["day"])

    def test_top_authors_sorted_desc_then_asc(self) -> None:
        recs = tool.parse_log(FIXTURE_LOG)
        agg = tool.aggregate(recs)
        authors = agg["top_authors"]
        self.assertEqual(authors[0]["author"], "Alice")  # 3 commits
        self.assertEqual(authors[0]["count"], 3)
        self.assertEqual(authors[1]["author"], "Bob")  # 2 commits
        self.assertEqual(authors[1]["count"], 2)

    def test_top_lanes_capped_and_hours_always_24(self) -> None:
        recs = tool.parse_log(FIXTURE_LOG)
        agg = tool.aggregate(recs)
        self.assertLessEqual(len(agg["top_lanes"]), tool.TOP_LANES)
        # hour_of_day always emits 24 buckets in canonical order.
        self.assertEqual(len(agg["hour_of_day"]), 24)
        hours = [item["hour"] for item in agg["hour_of_day"]]
        self.assertEqual(hours, list(range(24)))


class TestEnvelope(unittest.TestCase):
    def test_envelope_schema_and_keys(self) -> None:
        recs = tool.parse_log(FIXTURE_LOG)
        agg = tool.aggregate(recs)
        env = tool.build_envelope(
            agg,
            branch="origin/wave-1-hackerman-capability-lift",
            since="2026-05-08",
            generated_at="2026-05-16T05:00:00Z",
        )
        self.assertEqual(
            env["schema"], "auditooor.hackerman_pr726_density_analyzer.v1"
        )
        for required in (
            "branch",
            "since",
            "generated_at",
            "stats",
            "commits_per_day",
            "top_days",
            "top_authors",
            "top_lanes",
            "hour_of_day",
        ):
            self.assertIn(required, env)
        self.assertEqual(env["stats"]["total_commits"], 5)
        self.assertEqual(env["stats"]["distinct_days"], 3)


class TestCLI(unittest.TestCase):
    def test_cli_human_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "log.txt"
            log_path.write_text(FIXTURE_LOG, encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--log-file",
                    str(log_path),
                    "--generated-at",
                    "2026-05-16T05:00:00Z",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("PR #726 commit-density analyzer", proc.stdout)
            self.assertIn("total_commits: 5", proc.stdout)

    def test_cli_json_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "log.txt"
            log_path.write_text(FIXTURE_LOG, encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--log-file",
                    str(log_path),
                    "--json",
                    "--generated-at",
                    "2026-05-16T05:00:00Z",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            envelope = json.loads(proc.stdout)
            self.assertEqual(
                envelope["schema"],
                "auditooor.hackerman_pr726_density_analyzer.v1",
            )
            self.assertEqual(envelope["generated_at"], "2026-05-16T05:00:00Z")
            self.assertEqual(envelope["stats"]["total_commits"], 5)


if __name__ == "__main__":
    unittest.main()
