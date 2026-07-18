"""Tests for ``tools/hackerman-integrity-check.py`` (PR #726 Wave-1).

Coverage (>=10 cases):

1. All-pass: every stage returns rc=0 + pass-shaped envelope -> overall pass.
2. Schema-fail: schema stage exits non-zero -> overall fail.
3. Tier-fail: tier stage envelope has missing-tier > 0 -> overall fail.
4. Acceptance-fail: acceptance stage envelope has fail_count > 0 -> overall fail.
5. Dupe-fail: dupes stage returns non-exempt groups under --strict -> overall fail.
6. Missing-tool-stage: stage tool binary absent -> verdict=missing -> overall fail.
7. Deterministic-ordering: registry order preserved across two invocations.
8. JSON envelope shape: schema, generated_at, stages list, verdict_counts.
9. Human-output sanity: header, table, per-stage detail block present.
10. Single-stage filter: --stage <name> restricts to one stage only.
11. Unparseable JSON: a stage that emits garbage maps to verdict=error.
12. CLI --strict exits non-zero on overall fail.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-integrity-check.py"


def _load_tool() -> Any:
    name = "_hackerman_integrity_check_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_stub(target: Path, *, stdout: str, exit_code: int = 0, stderr: str = "") -> None:
    """Write a tiny Python stub that emits stdout/stderr + exits exit_code."""
    script = textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
        import sys
        sys.stdout.write({stdout!r})
        sys.stderr.write({stderr!r})
        sys.exit({exit_code})
        """
    )
    target.write_text(script, encoding="utf-8")
    target.chmod(0o755)


def _stub_spec(
    name: str,
    target: Path,
    *,
    parser,
    description: str = "stub stage",
) -> Any:
    return tool.StageSpec(
        name=name,
        # Absolute path so absolute_tool_path() returns target.
        tool_relpath=str(target),
        description=description,
        argv_builder=lambda ctx, _t=target: [sys.executable, str(_t)],
        result_parser=parser,
    )


# Pass-shaped envelopes for each parser.
_PASS_TIER_ENV = {
    "verdict": "pass",
    "audited_hackerman_v1": 1000,
    "verdict_counts": {"pass": 1000},
}
_PASS_ACCEPTANCE_ENV = {
    "directory_count": 10,
    "pass_count": 10,
    "fail_count": 0,
    "fail_exempt_count": 0,
}
_PASS_DUPES_ENV = {
    "groups": [],
    "summary": {
        "group_count": 0,
        "records_scanned": 100,
        "jsonl_out": "/tmp/integrity_dupes.jsonl",
    },
}
_PASS_STATS_ENV = {
    "stats": {
        "hackerman_v1_total": 1000,
        "hackerman_v1_by_shape": {"flat.yaml": 1000},
        "quarantine": {"total": 0},
    },
}
_PASS_DISTRIBUTION_ENV = {"class_totals": {"reentrancy": 50, "oracle-stale": 20}}


class _RegistryGuard:
    """Context manager that swaps the registry then restores it."""

    def __init__(self, specs: list) -> None:
        self._specs = specs
        self._saved: list = []

    def __enter__(self):
        self._saved = list(tool.HACKERMAN_INTEGRITY_STAGES)
        tool.HACKERMAN_INTEGRITY_STAGES.clear()
        tool.HACKERMAN_INTEGRITY_STAGES.extend(self._specs)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        tool.HACKERMAN_INTEGRITY_STAGES.clear()
        tool.HACKERMAN_INTEGRITY_STAGES.extend(self._saved)


# ---------------------------------------------------------------------------
# Parser unit tests.
# ---------------------------------------------------------------------------


class ParserTests(unittest.TestCase):
    def test_schema_parser_extracts_result_line(self) -> None:
        out = "OK\tfoo.yaml\nresult: valid=10 invalid=0 skipped=2\n"
        res = tool._parse_schema(0, out, "")
        self.assertEqual(res["verdict"], "pass")
        self.assertEqual(res["metrics"], {"valid": 10, "invalid": 0, "skipped": 2})

    def test_schema_parser_fail_on_nonzero_rc(self) -> None:
        res = tool._parse_schema(2, "result: valid=5 invalid=3 skipped=0\n", "")
        self.assertEqual(res["verdict"], "fail")

    def test_tier_parser_missing_tier_is_fail(self) -> None:
        env = {"verdict": "fail", "verdict_counts": {"pass": 100, "missing-tier": 3}}
        res = tool._parse_tier(0, json.dumps(env), "")
        self.assertEqual(res["verdict"], "fail")

    def test_tier_parser_quarantine_alone_is_pass(self) -> None:
        # Quarantine bucket existing is corpus-normal; respect tool's pass verdict.
        env = {
            "verdict": "pass",
            "audited_hackerman_v1": 1000,
            "verdict_counts": {"pass": 950, "quarantine": 50},
        }
        res = tool._parse_tier(0, json.dumps(env), "")
        self.assertEqual(res["verdict"], "pass")

    def test_acceptance_parser_fail_count_drives_verdict(self) -> None:
        env = {
            "directory_count": 5,
            "pass_count": 3,
            "fail_count": 1,
            "fail_exempt_count": 1,
        }
        res = tool._parse_acceptance(0, json.dumps(env), "")
        self.assertEqual(res["verdict"], "fail")

    def test_dupes_parser_collects_non_exempt_count(self) -> None:
        env = {
            "groups": [
                {"exempt": False, "identifier": "GHSA-aaaa"},
                {"exempt": True, "identifier": "GHSA-bbbb"},
                {"identifier": "GHSA-cccc"},  # missing exempt -> non-exempt
            ],
            "summary": {"group_count": 3, "records_scanned": 1234},
        }
        res = tool._parse_dupes(0, json.dumps(env), "")
        self.assertEqual(res["verdict"], "pass")  # advisory at parser level
        self.assertEqual(res["metrics"]["non_exempt_group_count"], 2)
        self.assertEqual(res["metrics"]["group_count"], 3)


# ---------------------------------------------------------------------------
# Integration tests with stub registry.
# ---------------------------------------------------------------------------


def _all_pass_stubs(tmpdir: Path) -> list:
    """Build a stub registry where every stage returns pass-shaped output."""
    layouts = [
        ("schema", "OK\tfoo.yaml\nresult: valid=10 invalid=0 skipped=0\n", tool._parse_schema),
        ("tier", json.dumps(_PASS_TIER_ENV), tool._parse_tier),
        ("acceptance", json.dumps(_PASS_ACCEPTANCE_ENV), tool._parse_acceptance),
        ("dupes", json.dumps(_PASS_DUPES_ENV), tool._parse_dupes),
        ("stats", json.dumps(_PASS_STATS_ENV), tool._parse_stats),
        ("distribution", json.dumps(_PASS_DISTRIBUTION_ENV), tool._parse_distribution),
    ]
    specs = []
    for name, out, parser in layouts:
        target = tmpdir / f"stub-{name}.py"
        _write_stub(target, stdout=out, exit_code=0)
        specs.append(_stub_spec(name, target, parser=parser))
    return specs


class IntegrationTests(unittest.TestCase):
    def test_all_pass_overall_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            with _RegistryGuard(_all_pass_stubs(tmpdir)):
                rows = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                env = tool.build_envelope(
                    rows, generated_at="2026-05-16T00:00:00Z", strict=False
                )
                self.assertEqual(env["overall_verdict"], "pass")
                self.assertEqual(env["stage_count"], 6)
                self.assertEqual(env["verdict_counts"]["pass"], 6)

    def test_schema_fail_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            specs = _all_pass_stubs(tmpdir)
            # Replace schema stub with a rc=1 variant.
            target = tmpdir / "stub-schema-fail.py"
            _write_stub(
                target,
                stdout="result: valid=8 invalid=2 skipped=0\n",
                exit_code=1,
            )
            specs[0] = _stub_spec("schema", target, parser=tool._parse_schema)
            with _RegistryGuard(specs):
                rows = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                env = tool.build_envelope(rows, generated_at="2026-05-16T00:00:00Z")
                self.assertEqual(env["overall_verdict"], "fail")
                self.assertEqual(rows[0]["verdict"], "fail")

    def test_tier_fail_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            specs = _all_pass_stubs(tmpdir)
            target = tmpdir / "stub-tier-fail.py"
            bad_env = {
                "verdict": "fail",
                "audited_hackerman_v1": 1000,
                "verdict_counts": {"pass": 990, "missing-tier": 10},
            }
            _write_stub(target, stdout=json.dumps(bad_env), exit_code=0)
            specs[1] = _stub_spec("tier", target, parser=tool._parse_tier)
            with _RegistryGuard(specs):
                rows = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                env = tool.build_envelope(rows, generated_at="2026-05-16T00:00:00Z")
                self.assertEqual(env["overall_verdict"], "fail")
                self.assertEqual(rows[1]["verdict"], "fail")

    def test_acceptance_fail_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            specs = _all_pass_stubs(tmpdir)
            target = tmpdir / "stub-acc-fail.py"
            bad_env = {
                "directory_count": 5,
                "pass_count": 4,
                "fail_count": 1,
                "fail_exempt_count": 0,
            }
            _write_stub(target, stdout=json.dumps(bad_env), exit_code=0)
            specs[2] = _stub_spec("acceptance", target, parser=tool._parse_acceptance)
            with _RegistryGuard(specs):
                rows = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                env = tool.build_envelope(rows, generated_at="2026-05-16T00:00:00Z")
                self.assertEqual(env["overall_verdict"], "fail")

    def test_dupe_fail_under_strict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            specs = _all_pass_stubs(tmpdir)
            target = tmpdir / "stub-dupes-bad.py"
            bad_env = {
                "groups": [{"exempt": False, "identifier": "GHSA-xxxx"}],
                "summary": {"group_count": 1, "records_scanned": 100},
            }
            _write_stub(target, stdout=json.dumps(bad_env), exit_code=0)
            specs[3] = _stub_spec("dupes", target, parser=tool._parse_dupes)
            with _RegistryGuard(specs):
                rows = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                env_strict = tool.build_envelope(
                    rows, generated_at="2026-05-16T00:00:00Z", strict=True
                )
                env_loose = tool.build_envelope(
                    rows, generated_at="2026-05-16T00:00:00Z", strict=False
                )
                self.assertEqual(env_strict["overall_verdict"], "fail")
                # Without --strict, a non-exempt dupe group is advisory only.
                self.assertEqual(env_loose["overall_verdict"], "pass")

    def test_missing_tool_stage_yields_missing_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            ghost = tool.StageSpec(
                name="ghost",
                tool_relpath=str(tmpdir / "does-not-exist-xyz.py"),
                description="ghost",
                argv_builder=lambda ctx: [sys.executable, "missing.py"],
                result_parser=tool._parse_schema,
            )
            with _RegistryGuard([ghost]):
                rows = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                self.assertEqual(rows[0]["verdict"], "missing")
                env = tool.build_envelope(rows, generated_at="2026-05-16T00:00:00Z")
                self.assertEqual(env["overall_verdict"], "fail")

    def test_deterministic_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            with _RegistryGuard(_all_pass_stubs(tmpdir)):
                rows1 = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                rows2 = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                self.assertEqual(
                    [r["name"] for r in rows1],
                    ["schema", "tier", "acceptance", "dupes", "stats", "distribution"],
                )
                self.assertEqual(
                    [r["name"] for r in rows1],
                    [r["name"] for r in rows2],
                )

    def test_json_envelope_shape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            with _RegistryGuard(_all_pass_stubs(tmpdir)):
                rows = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                env = tool.build_envelope(rows, generated_at="2026-05-16T00:00:00Z")
                self.assertEqual(env["schema"], "auditooor.hackerman_integrity_check.v1")
                self.assertEqual(env["generated_at"], "2026-05-16T00:00:00Z")
                self.assertIn("verdict_counts", env)
                self.assertIn("stages", env)
                self.assertEqual(len(env["stages"]), 6)
                # Every stage row has the canonical key set.
                for row in env["stages"]:
                    for key in ("name", "tool", "description", "verdict", "rc", "summary", "metrics"):
                        self.assertIn(key, row)

    def test_human_output_sanity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            with _RegistryGuard(_all_pass_stubs(tmpdir)):
                rows = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                env = tool.build_envelope(rows, generated_at="2026-05-16T00:00:00Z")
                text = tool.render_report(env)
                self.assertIn("hackerman integrity check", text)
                self.assertIn("STAGE", text)
                self.assertIn("VERDICT", text)
                self.assertIn("## Per-stage detail", text)
                for stage_name in ("schema", "tier", "acceptance", "dupes", "stats", "distribution"):
                    self.assertIn(stage_name, text)

    def test_single_stage_filter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            with _RegistryGuard(_all_pass_stubs(tmpdir)):
                rows = tool.run_stages(
                    dupes_jsonl_out=tmpdir / "dupes.jsonl",
                    selected=["stats"],
                )
                self.assertEqual([r["name"] for r in rows], ["stats"])

    def test_unparseable_json_maps_to_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            target = tmpdir / "stub-garbage.py"
            _write_stub(target, stdout="not-json-at-all", exit_code=0)
            spec = _stub_spec("tier", target, parser=tool._parse_tier)
            with _RegistryGuard([spec]):
                rows = tool.run_stages(dupes_jsonl_out=tmpdir / "dupes.jsonl")
                self.assertEqual(rows[0]["verdict"], "error")


# ---------------------------------------------------------------------------
# CLI integration tests.
# ---------------------------------------------------------------------------


class CLITests(unittest.TestCase):
    def test_cli_strict_exits_nonzero_when_no_stage_matches(self) -> None:
        # An unknown --stage filter empties the run -> overall='empty' != 'pass'.
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--stage",
                "no-such-stage-zzz",
                "--strict",
                "--generated-at",
                "2026-05-16T00:00:00Z",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_cli_emits_valid_json_when_filtered_to_fast_stage(self) -> None:
        # Run only the fastest stage (stats) end-to-end against the real corpus.
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--stage",
                "stats",
                "--json",
                "--generated-at",
                "2026-05-16T00:00:00Z",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        env = json.loads(proc.stdout)
        self.assertEqual(env["schema"], "auditooor.hackerman_integrity_check.v1")
        self.assertEqual(env["generated_at"], "2026-05-16T00:00:00Z")
        self.assertEqual(env["stage_count"], 1)
        self.assertEqual(env["stages"][0]["name"], "stats")


if __name__ == "__main__":
    unittest.main()
