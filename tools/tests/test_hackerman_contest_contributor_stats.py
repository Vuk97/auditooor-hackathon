"""Tests for ``tools/hackerman-contest-contributor-stats.py``.

Wave-1 hackerman capability lift (PR #726). The tool walks
``audit/corpus_tags/tags/contest_platform_findings/**/record.{yaml,json}``
and aggregates per-contributor (warden / submitter handle) finding counts.

Cases (>=8 required by the task brief):

1.  empty tags-dir -> total_records=0, contributors_total=0, render_report
    survives (no crash on empty corpus).
2.  single Code4rena record with explicit "Reported by handle <name>" in
    required_preconditions -> handle extracted, per_platform[code4rena]=1.
3.  Sherlock fallback: handle parsed from "<title>. <Warden> <severity> #"
    inside attacker_action_sequence when required_preconditions absent.
4.  multi-contributor aggregation across both platforms, ranked desc by
    total with tie-break asc by handle.
5.  unknown-handle sentinel when neither precondition channel nor
    Sherlock AAS pattern fire -> bumps unknown_handle_records counter.
6.  severity weighting: critical=5, high=3, medium=1, low=0.3, info=0.1
    drive top_by_score independent of top_by_count (verified via two
    handles where score-ranking != count-ranking).
7.  cross_platform list surfaces only contributors active on >=2
    platforms (sorted by total desc, tie-break asc handle).
8.  record.yaml wins over record.json in the same directory (sibling
    precedence -- mirrors hackerman-target-repo-stats behaviour).
9.  JSON envelope schema is exactly
    ``auditooor.hackerman_contest_contributor_stats.v1`` with the
    canonical key set (stats.total_records / per_platform / top_by_count
    / top_by_score / cross_platform / severity_weights).
10. CLI default human render exit-code 0 on a populated synthetic corpus
    and emits the canonical title.
11. CLI ``--json`` emits valid JSON on stdout with the canonical schema
    + generated_at override flag honoured (deterministic timestamp).
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-contest-contributor-stats.py"


def _load_tool() -> Any:
    name = "_hackerman_contest_contributor_stats_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_record(
    tags_dir: Path,
    record_id: str,
    *,
    attack_class: str = "contest-platform-finding-code4rena",
    source_audit_ref: str | None = None,
    severity: str = "medium",
    preconditions: list[str] | None = None,
    attacker_action_sequence: str | None = None,
    fmt: str = "json",
) -> Path:
    """Write a synthetic record under ``tags_dir/<record_id>/record.<fmt>``.

    Defaults to JSON (less brittle for tests than the fallback YAML
    parser). Use ``fmt='yaml'`` for the precedence test.
    """
    rec_dir = tags_dir / record_id
    rec_dir.mkdir(parents=True, exist_ok=True)
    obj: dict[str, Any] = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "attack_class": attack_class,
        "severity_at_finding": severity,
    }
    if source_audit_ref is not None:
        obj["source_audit_ref"] = source_audit_ref
    if preconditions is not None:
        obj["required_preconditions"] = preconditions
    if attacker_action_sequence is not None:
        obj["attacker_action_sequence"] = attacker_action_sequence
    if fmt == "yaml":
        # Minimal YAML matching the fallback parser shape.
        lines = [
            f"schema_version: {obj['schema_version']}",
            f"record_id: {record_id}",
            f"attack_class: {attack_class}",
            f"severity_at_finding: {severity}",
        ]
        if source_audit_ref is not None:
            lines.append(f"source_audit_ref: {source_audit_ref}")
        if attacker_action_sequence is not None:
            # Avoid embedded colons confusing the fallback parser; wrap
            # in a single-quoted scalar so PyYAML (if available) treats
            # it as a string literal.
            esc = attacker_action_sequence.replace("'", "''")
            lines.append(f"attacker_action_sequence: '{esc}'")
        if preconditions is not None:
            lines.append("required_preconditions:")
            for pre in preconditions:
                lines.append(f"  - {pre}")
        path = rec_dir / "record.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path
    path = rec_dir / "record.json"
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


class HackermanContestContributorStatsTests(unittest.TestCase):
    # ----- Case 1 -----
    def test_01_empty_tags_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 0)
            self.assertEqual(stats["contributors_total"], 0)
            self.assertEqual(stats["unknown_handle_records"], 0)
            self.assertEqual(stats["top_by_count"], [])
            self.assertEqual(stats["top_by_score"], [])
            self.assertEqual(stats["cross_platform"], [])
            # render_report must not crash on empty corpus.
            report = tool.render_report(stats, generated_at="2026-05-16T00:00:00Z")
            self.assertIn("Hackerman contest-platform contributor stats", report)
            self.assertIn("total_records: 0", report)

    # ----- Case 2 -----
    def test_02_code4rena_handle_via_preconditions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_record(
                tags, "c4_001",
                attack_class="contest-platform-finding-code4rena",
                source_audit_ref="code4rena:2024-07-loopfi-findings:473",
                severity="medium",
                preconditions=[
                    "Reference finding at https://example.test/issues/1",
                    "Reported by handle 0xINFINITY",
                    "verification_tier=tier-2-verified-public-archive",
                ],
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["unknown_handle_records"], 0)
            self.assertEqual(stats["contributors_total"], 1)
            self.assertIn("0xINFINITY", stats["contributors"])
            self.assertEqual(stats["contributors"]["0xINFINITY"]["total"], 1)
            self.assertEqual(stats["per_platform"]["code4rena"]["records"], 1)
            self.assertEqual(
                stats["per_platform"]["code4rena"]["distinct_contributors"], 1
            )

    # ----- Case 3 -----
    def test_03_sherlock_handle_via_aas_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # Sherlock AAS prefix shape: "<title>. <Warden> <severity> # <title> ..."
            aas = (
                "Pool deposit handling diverges from spec. WardenAlice high "
                "# Pool deposit handling diverges from spec for blah blah."
            )
            _write_record(
                tags, "sh_001",
                attack_class="contest-platform-finding-sherlock",
                source_audit_ref="sherlock:2024-foobar:42",
                severity="high",
                preconditions=None,
                attacker_action_sequence=aas,
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertIn("WardenAlice", stats["contributors"])
            self.assertEqual(stats["contributors"]["WardenAlice"]["total"], 1)
            self.assertEqual(stats["per_platform"]["sherlock"]["records"], 1)

    # ----- Case 4 -----
    def test_04_multi_contributor_ranking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # alice: 3 findings, bob: 2 findings, carol: 1 finding.
            for i in range(3):
                _write_record(
                    tags, f"c4_alice_{i}",
                    severity="medium",
                    preconditions=["Reported by handle alice"],
                )
            for i in range(2):
                _write_record(
                    tags, f"c4_bob_{i}",
                    severity="medium",
                    preconditions=["Reported by handle bob"],
                )
            _write_record(
                tags, "c4_carol_0",
                severity="medium",
                preconditions=["Reported by handle carol"],
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 6)
            self.assertEqual(stats["contributors_total"], 3)
            top = [r["handle"] for r in stats["top_by_count"]]
            self.assertEqual(top, ["alice", "bob", "carol"])
            self.assertEqual(stats["top_by_count"][0]["total"], 3)
            self.assertEqual(stats["top_by_count"][1]["total"], 2)
            self.assertEqual(stats["top_by_count"][2]["total"], 1)

    # ----- Case 5 -----
    def test_05_unknown_handle_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # No precondition handle line, no Sherlock AAS pattern.
            _write_record(
                tags, "mystery_001",
                attack_class="contest-platform-finding-code4rena",
                source_audit_ref="code4rena:foo:1",
                severity="low",
                preconditions=["some unrelated precondition"],
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["unknown_handle_records"], 1)
            self.assertIn(tool.UNKNOWN_HANDLE, stats["contributors"])

    # ----- Case 6 -----
    def test_06_severity_score_ranking_differs_from_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # alice: 1 critical (score=5)
            # bob:   3 lows    (score=0.9)
            # alice should rank #1 by score, bob #1 by count.
            _write_record(
                tags, "c4_alice_crit",
                severity="critical",
                preconditions=["Reported by handle alice"],
            )
            for i in range(3):
                _write_record(
                    tags, f"c4_bob_{i}",
                    severity="low",
                    preconditions=["Reported by handle bob"],
                )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 4)
            # By count: bob first (3 > 1).
            self.assertEqual(stats["top_by_count"][0]["handle"], "bob")
            # By score: alice first (5.0 > 0.9).
            self.assertEqual(stats["top_by_score"][0]["handle"], "alice")
            self.assertAlmostEqual(
                stats["contributors"]["alice"]["score"], 5.0, places=3
            )
            self.assertAlmostEqual(
                stats["contributors"]["bob"]["score"], 0.9, places=3
            )

    # ----- Case 7 -----
    def test_07_cross_platform_contributors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # alice active on both code4rena AND sherlock; bob only c4.
            _write_record(
                tags, "c4_alice_a",
                attack_class="contest-platform-finding-code4rena",
                severity="medium",
                preconditions=["Reported by handle alice"],
            )
            _write_record(
                tags, "sh_alice_b",
                attack_class="contest-platform-finding-sherlock",
                source_audit_ref="sherlock:proj:1",
                severity="high",
                preconditions=["Reported by handle alice"],
            )
            _write_record(
                tags, "c4_bob_a",
                attack_class="contest-platform-finding-code4rena",
                severity="medium",
                preconditions=["Reported by handle bob"],
            )
            stats = tool.build_stats(tags)
            cross_handles = [r["handle"] for r in stats["cross_platform"]]
            self.assertEqual(cross_handles, ["alice"])
            self.assertEqual(
                sorted(stats["contributors"]["alice"]["platforms"]),
                ["code4rena", "sherlock"],
            )

    # ----- Case 8 -----
    def test_08_yaml_wins_over_json_in_same_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # Write YAML claiming alice; JSON claiming bob in same dir.
            _write_record(
                tags, "dup_dir",
                severity="medium",
                preconditions=["Reported by handle alice"],
                fmt="yaml",
            )
            _write_record(
                tags, "dup_dir",
                severity="medium",
                preconditions=["Reported by handle bob"],
                fmt="json",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertIn("alice", stats["contributors"])
            self.assertNotIn("bob", stats["contributors"])

    # ----- Case 9 -----
    def test_09_json_envelope_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_record(
                tags, "c4_001",
                severity="medium",
                preconditions=["Reported by handle alice"],
            )
            result = subprocess.run(
                [
                    sys.executable, str(TOOL_PATH),
                    "--tags-dir", str(tags),
                    "--json",
                    "--generated-at", "2026-05-16T00:00:00Z",
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_contest_contributor_stats.v1",
            )
            self.assertEqual(payload["generated_at"], "2026-05-16T00:00:00Z")
            stats = payload["stats"]
            self.assertEqual(stats["total_records"], 1)
            for key in (
                "per_platform", "contributors", "top_by_count",
                "top_by_score", "cross_platform", "severity_weights",
                "unknown_handle_records",
            ):
                self.assertIn(key, stats)
            self.assertEqual(stats["severity_weights"]["critical"], 5.0)
            self.assertEqual(stats["severity_weights"]["high"], 3.0)
            self.assertEqual(stats["severity_weights"]["medium"], 1.0)

    # ----- Case 10 -----
    def test_10_cli_human_exit_code_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_record(
                tags, "c4_001",
                severity="medium",
                preconditions=["Reported by handle alice"],
            )
            result = subprocess.run(
                [
                    sys.executable, str(TOOL_PATH),
                    "--tags-dir", str(tags),
                    "--generated-at", "2026-05-16T00:00:00Z",
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn(
                "Hackerman contest-platform contributor stats",
                result.stdout,
            )
            self.assertIn("alice", result.stdout)

    # ----- Case 11 -----
    def test_11_cli_missing_tags_dir_returns_nonzero(self) -> None:
        # tags_dir that does not exist -> exit code 2.
        result = subprocess.run(
            [
                sys.executable, str(TOOL_PATH),
                "--tags-dir", "/tmp/__definitely_does_not_exist_12345__",
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("tags_dir not found", result.stderr)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
