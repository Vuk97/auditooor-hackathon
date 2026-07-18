"""Tests for ``tools/hackerman-all.py`` (PR #726 Wave-1 aggregator).

The aggregator chains seven subprocess stages. To keep tests fast and
deterministic the suite drives the module-level helpers directly with
stubbed ``StageResult`` records (parsers + verdict aggregation +
envelope shape are pure functions), and exercises the CLI in a single
synthetic-pattern subprocess sanity check that runs only the cheapest
stage (``--stage stats`` with a tiny synthetic tags dir).

Coverage (>=8 cases):

1. ``_parse_schema_summary`` extracts the trailing ``result:`` line.
2. ``_parse_tier_summary`` returns pass when JSON has failed_records=[].
3. ``_parse_tier_summary`` returns fail when rc!=0.
4. ``_parse_acceptance_summary`` returns fail when rc!=0 (non-exempt failure).
5. ``_parse_acceptance_summary`` returns pass when rc=0.
6. ``_parse_unittest_summary`` parses ``Ran N tests`` / ``OK`` / ``FAILED``.
7. ``overall_verdict`` returns pass only when every stage is pass/skipped.
8. ``build_json_envelope`` shape matches ``auditooor.hackerman_all.v1``.
9. CLI ``--stage stats --json`` round-trip on a synthetic tree.
10. CLI ``--stage <unknown>`` rejected by argparse.
11. Determinism: byte-identical JSON for two consecutive runs when
    ``--generated-at`` is pinned.
12. ``run_stage_integrity`` returns ``skipped`` when the tool file is missing.
13. ``--strict`` exits 1 when overall != pass.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-all.py"


def _load_tool() -> Any:
    name = "_hackerman_all_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _result(stage: str, verdict: str, rc: int = 0, summary: str = "ok") -> Any:
    return tool.StageResult(
        stage=stage,
        label=f"label for {stage}",
        verdict=verdict,
        returncode=rc,
        summary=summary,
        duration_seconds=0.01,
        stdout_tail="",
        stderr_tail="",
        cmd=[],
    )


class ParserTests(unittest.TestCase):
    def test_parse_schema_summary_trailing_line(self):
        stdout = "...\nresult: valid=42 invalid=0 skipped=3\n"
        self.assertEqual(
            tool._parse_schema_summary(stdout),
            "result: valid=42 invalid=0 skipped=3",
        )

    def test_parse_schema_summary_missing(self):
        self.assertEqual(tool._parse_schema_summary("nothing here\n"), "")

    def test_parse_tier_summary_pass(self):
        payload = json.dumps(
            {
                "audited_hackerman_v1": 41100,
                "failed_records": [],
                "quarantine_records": [],
            }
        )
        summary, verdict = tool._parse_tier_summary(payload, 0)
        self.assertEqual(verdict, "pass")
        self.assertIn("audited=41100", summary)
        self.assertIn("failed=0", summary)

    def test_parse_tier_summary_fail_when_rc_nonzero(self):
        payload = json.dumps(
            {"audited_hackerman_v1": 1, "failed_records": [{"x": 1}], "quarantine_records": []}
        )
        _, verdict = tool._parse_tier_summary(payload, 1)
        self.assertEqual(verdict, "fail")

    def test_parse_tier_summary_invalid_json(self):
        summary, verdict = tool._parse_tier_summary("not json", 1)
        self.assertEqual(verdict, "fail")
        self.assertIn("JSON parse failed", summary)

    def test_parse_acceptance_summary_pass(self):
        payload = json.dumps(
            {
                "directory_count": 34,
                "fail_count": 1,
                "fail_exempt_count": 11,
                "exemptions_loaded": 13,
            }
        )
        # rc==0 means the strict gate accepted the result (any failures are exempt).
        summary, verdict = tool._parse_acceptance_summary(payload, 0)
        self.assertEqual(verdict, "pass")
        self.assertIn("subtrees=34", summary)
        self.assertIn("fails=1", summary)

    def test_parse_acceptance_summary_fail_when_rc_nonzero(self):
        payload = json.dumps(
            {
                "directory_count": 10,
                "fail_count": 2,
                "fail_exempt_count": 0,
                "exemptions_loaded": 0,
            }
        )
        _, verdict = tool._parse_acceptance_summary(payload, 1)
        self.assertEqual(verdict, "fail")

    def test_parse_unittest_summary_ok(self):
        stream = "....\nRan 12 tests in 0.456s\n\nOK\n"
        self.assertTrue(tool._parse_unittest_summary(stream).startswith("ok "))

    def test_parse_unittest_summary_failed(self):
        stream = "F.\nRan 2 tests in 0.001s\n\nFAILED (failures=1)\n"
        self.assertTrue(tool._parse_unittest_summary(stream).startswith("fail "))

    def test_parse_unittest_summary_empty(self):
        self.assertIn("no unittest summary", tool._parse_unittest_summary(""))


class AggregationTests(unittest.TestCase):
    def test_overall_verdict_all_pass(self):
        results = [_result("a", "pass"), _result("b", "pass"), _result("c", "skipped")]
        self.assertEqual(tool.overall_verdict(results), "pass")

    def test_overall_verdict_any_fail(self):
        results = [_result("a", "pass"), _result("b", "fail")]
        self.assertEqual(tool.overall_verdict(results), "fail")

    def test_overall_verdict_any_error(self):
        results = [_result("a", "pass"), _result("b", "error")]
        self.assertEqual(tool.overall_verdict(results), "fail")

    def test_overall_verdict_empty(self):
        self.assertEqual(tool.overall_verdict([]), "fail")

    def test_build_json_envelope_shape(self):
        results = [
            _result("schema", "pass", summary="result: valid=10 invalid=0 skipped=0"),
            _result("tier", "pass", summary="audited=10 failed=0 quarantined=0"),
            _result("integrity", "skipped", summary="absent"),
        ]
        payload = tool.build_json_envelope(
            results, generated_at="2026-05-16T00:00:00Z", tags_dir=Path("/tmp/x")
        )
        self.assertEqual(payload["schema"], tool.SCHEMA)
        self.assertEqual(payload["generated_at"], "2026-05-16T00:00:00Z")
        self.assertEqual(payload["overall_verdict"], "pass")
        self.assertEqual(payload["stage_count"], 3)
        self.assertEqual(len(payload["stages"]), 3)
        self.assertEqual(payload["stages"][0]["stage"], "schema")
        self.assertEqual(payload["stages"][2]["verdict"], "skipped")

    def test_render_report_contains_all_stages(self):
        results = [
            _result("schema", "pass"),
            _result("tier", "pass"),
            _result("acceptance", "pass"),
            _result("unit-tests", "pass"),
            _result("vault-tests", "pass"),
            _result("stats", "pass"),
            _result("integrity", "skipped"),
        ]
        report = tool.render_report(
            results,
            generated_at="2026-05-16T00:00:00Z",
            overall="pass",
            tags_dir=Path("/tmp/x"),
        )
        for r in results:
            self.assertIn(r.stage, report)
        self.assertIn("overall_verdict: pass", report)
        self.assertIn(tool.SCHEMA, report)
        # Output stays well under 1MB.
        self.assertLess(len(report.encode("utf-8")), 1_000_000)


def _make_tiny_tags_dir(tmp: Path) -> Path:
    tags = tmp / "audit" / "corpus_tags" / "tags"
    bucket = tags / "tiny_bucket"
    bucket.mkdir(parents=True, exist_ok=True)
    record_yaml = """schema_version: auditooor.hackerman_record.v1
record_id: tiny-1
target_domain: vault
attack_class: synthetic
function_shape:
  raw_signature: synthetic
  shape_tags:
    - verification_tier:tier-1-verified-realtime-api
    - synthetic-test
"""
    (bucket / "rec.yaml").write_text(record_yaml, encoding="utf-8")
    return tags


class CLITests(unittest.TestCase):
    def test_cli_stage_stats_only_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tags = _make_tiny_tags_dir(Path(tmp))
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags),
                    "--stage",
                    "stats",
                    "--json",
                    "--generated-at",
                    "2026-05-16T00:00:00Z",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], tool.SCHEMA)
            self.assertEqual(payload["generated_at"], "2026-05-16T00:00:00Z")
            self.assertEqual(payload["stage_count"], 1)
            self.assertEqual(payload["stages"][0]["stage"], "stats")
            self.assertEqual(payload["overall_verdict"], "pass")

    def test_cli_unknown_stage_rejected(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--stage",
                "no-such-stage",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("invalid choice", proc.stderr)

    def test_cli_deterministic_when_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            tags = _make_tiny_tags_dir(Path(tmp))
            cmd = [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(tags),
                "--stage",
                "stats",
                "--json",
                "--generated-at",
                "2026-05-16T00:00:00Z",
            ]
            first = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            second = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(first.returncode, 0, msg=first.stderr)
            self.assertEqual(second.returncode, 0, msg=second.stderr)
            # Stable JSON.
            j1 = json.loads(first.stdout)
            j2 = json.loads(second.stdout)
            # Discard duration_seconds (wall-clock) from both before comparing.
            for j in (j1, j2):
                for s in j["stages"]:
                    s["duration_seconds"] = 0.0
            self.assertEqual(j1, j2)

    def test_cli_strict_exits_nonzero_when_fail(self):
        # Drive --strict by pointing the schema stage at a corpus dir that
        # contains an obviously invalid hackerman record.
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp) / "audit" / "corpus_tags" / "tags"
            tags.mkdir(parents=True)
            # Declare hackerman schema but omit required fields -> invalid.
            (tags / "broken.yaml").write_text(
                "schema_version: auditooor.hackerman_record.v1\nrecord_id: x\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags),
                    "--stage",
                    "schema",
                    "--strict",
                    "--generated-at",
                    "2026-05-16T00:00:00Z",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("schema", proc.stdout)


class IntegrityStageTests(unittest.TestCase):
    def test_integrity_skipped_when_tool_missing(self):
        # Build an args namespace pointing to a fake REPO_ROOT-relative path
        # where the integrity tool does not exist. Easiest is to monkey-patch
        # the module's REPO_ROOT and call run_stage_integrity directly.
        with tempfile.TemporaryDirectory() as tmp:
            fake_root = Path(tmp)
            (fake_root / "tools").mkdir()
            orig_root = tool.REPO_ROOT
            try:
                tool.REPO_ROOT = fake_root
                args = type("A", (), {})()
                args.tags_dir = fake_root / "audit" / "corpus_tags" / "tags"
                args.generated_at = "2026-05-16T00:00:00Z"
                args.timeout = 10
                r = tool.run_stage_integrity(args)
                self.assertEqual(r.verdict, "skipped")
                self.assertEqual(r.returncode, 0)
                self.assertIn("not present", r.summary)
            finally:
                tool.REPO_ROOT = orig_root


if __name__ == "__main__":
    unittest.main()
