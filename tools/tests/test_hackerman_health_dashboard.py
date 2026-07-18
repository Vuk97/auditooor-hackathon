"""Tests for ``tools/hackerman-health-dashboard.py`` (PR #726 Wave-1).

Coverage (>=8 cases):

1. All-pass: every axis returns a pass-shaped JSON envelope -> overall pass.
2. One axis FAIL: overall verdict demotes to fail.
3. Missing tool (FileNotFoundError) -> axis verdict=missing.
4. Subprocess timeout -> axis verdict=error.
5. Garbage stdout -> axis verdict=error (json decode).
6. Axis filter (--axis) restricts to the requested subset only.
7. JSON envelope shape: schema, generated_at, axes, overall_verdict,
   verdict_counts.
8. Human render is <= max_lines (default 80) AND obeys --max-lines override.
9. CLI --strict exits non-zero on overall fail.
10. Determinism: declaration order preserved across two invocations.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-health-dashboard.py"


def _load_tool() -> Any:
    name = "_hackerman_health_dashboard_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _write_stub(target: Path, *, stdout: str, exit_code: int = 0, stderr: str = "") -> None:
    """Tiny Python stub that emits stdout/stderr + exits exit_code."""
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


def _stub_axis(name: str, target: Path, parser, timeout_seconds: int = 30) -> Any:
    return tool.AxisSpec(
        name=name,
        description=f"stub-{name}",
        argv_builder=lambda ctx, _t=target: [sys.executable, str(_t)],
        result_parser=parser,
        timeout_seconds=timeout_seconds,
    )


_PASS_CORPUS_ENV = {
    "stats": {
        "total_records": 1000,
        "hackerman_v1_total": 950,
        "quarantine": {"total": 5},
        "subtrees": {"solodit": {}, "code4rena": {}},
    },
    "acceptance_gate": {
        "rc": 0,
        "verdict": "<no-verdict>",
        "summary": "dirs=10 pass=10 fail=0",
    },
    "verification_tier_gate": {
        "rc": 0,
        "verdict": "pass",
        "summary": "audited=1000",
    },
}

_PASS_GATES_ENV = {
    "overall_verdict": "pass",
    "gate_count": 2,
    "verdict_counts": {"pass": 2},
    "gates": [
        {"name": "tier-check", "summary": "rc=0 pass=1000", "rc": 0},
        {"name": "acceptance", "summary": "rc=0 dirs=10 pass=10", "rc": 0},
    ],
}

_FAIL_GATES_ENV = {
    "overall_verdict": "fail",
    "gate_count": 2,
    "verdict_counts": {"pass": 1, "fail": 1},
    "gates": [
        {"name": "tier-check", "summary": "rc=0 pass=1000", "rc": 0},
        {"name": "acceptance", "summary": "rc=1 fail=3", "rc": 1},
    ],
}

_PASS_INTEGRITY_ENV = {
    "overall_verdict": "pass",
    "stage_count": 6,
    "verdict_counts": {"pass": 6},
    "stages": [
        {"name": "schema", "verdict": "pass", "summary": "rc=0 valid=10"},
        {"name": "tier", "verdict": "pass", "summary": "rc=0 audited=1000"},
        {"name": "acceptance", "verdict": "pass", "summary": "rc=0 dirs=10"},
    ],
}

_PASS_MCP_ENV = {
    "schema": "auditooor.hackerman_mcp_smoke_test.v1",
    "wave": "wave-1",
    "callables_total": 3,
    "callables_passed": 3,
    "callables_failed": 0,
    "all_passed": True,
    "results": [
        {"name": "vault_corpus_search", "passed": True, "elapsed_seconds": 0.10},
        {"name": "vault_attack_class_taxonomy", "passed": True, "elapsed_seconds": 0.12},
        {"name": "vault_dupe_advisory_check", "passed": True, "elapsed_seconds": 0.09},
    ],
}


def _all_pass_specs(tmpdir: Path) -> list:
    layouts = [
        ("corpus", json.dumps(_PASS_CORPUS_ENV), tool._parse_corpus_stats),
        ("gates", json.dumps(_PASS_GATES_ENV), tool._parse_gates_status),
        ("integrity", json.dumps(_PASS_INTEGRITY_ENV), tool._parse_integrity_check),
        ("mcp-smoke", json.dumps(_PASS_MCP_ENV), tool._parse_mcp_smoke),
    ]
    out = []
    for name, payload, parser in layouts:
        target = tmpdir / f"stub-{name}.py"
        _write_stub(target, stdout=payload, exit_code=0)
        out.append(_stub_axis(name, target, parser))
    return out


# ---------------------------------------------------------------------------
# Parser unit tests.
# ---------------------------------------------------------------------------


class ParserTests(unittest.TestCase):
    def test_corpus_parser_pass_shape(self) -> None:
        verdict, summary, detail = tool._parse_corpus_stats(_PASS_CORPUS_ENV)
        self.assertEqual(verdict, tool.VERDICT_PASS)
        self.assertIn("records=1000", summary)
        self.assertIn("quarantine=5", summary)
        self.assertTrue(any("tier_gate" in d for d in detail))

    def test_gates_parser_overall_fail_propagates(self) -> None:
        verdict, summary, detail = tool._parse_gates_status(_FAIL_GATES_ENV)
        self.assertEqual(verdict, tool.VERDICT_FAIL)
        self.assertIn("fail=1", summary)

    def test_mcp_parser_handles_missing_top_level_counts(self) -> None:
        env = {
            "results": [
                {"name": "a", "passed": True, "elapsed_seconds": 0.1},
                {"name": "b", "passed": False, "elapsed_seconds": 0.2},
            ]
        }
        verdict, summary, _ = tool._parse_mcp_smoke(env)
        self.assertEqual(verdict, tool.VERDICT_FAIL)
        self.assertIn("callables=2", summary)
        self.assertIn("pass=1", summary)


# ---------------------------------------------------------------------------
# Integration tests with stub axes.
# ---------------------------------------------------------------------------


class IntegrationTests(unittest.TestCase):
    def test_all_pass_overall_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            specs = _all_pass_specs(Path(td))
            results = tool.run_dashboard(axes=specs, ctx={})
            self.assertEqual(len(results), 4)
            for r in results:
                self.assertEqual(r.verdict, tool.VERDICT_PASS, msg=r.name)
            self.assertEqual(tool.overall_verdict(results), tool.VERDICT_PASS)

    def test_one_axis_fail_demotes_overall(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            specs = _all_pass_specs(tmpdir)
            # Swap the gates axis for a fail-shaped stub.
            fail_target = tmpdir / "stub-gates-fail.py"
            _write_stub(fail_target, stdout=json.dumps(_FAIL_GATES_ENV), exit_code=0)
            specs[1] = _stub_axis("gates", fail_target, tool._parse_gates_status)
            results = tool.run_dashboard(axes=specs, ctx={})
            self.assertEqual(tool.overall_verdict(results), tool.VERDICT_FAIL)
            # Other axes still ran (no short-circuit).
            self.assertEqual(len(results), 4)
            gates = next(r for r in results if r.name == "gates")
            self.assertEqual(gates.verdict, tool.VERDICT_FAIL)

    def test_missing_tool_marks_axis_missing(self) -> None:
        bogus_path = Path("/nonexistent/path/that/does/not/exist/tool.py")
        spec = tool.AxisSpec(
            name="corpus",
            description="stub-corpus-missing",
            argv_builder=lambda ctx: [str(bogus_path)],
            result_parser=tool._parse_corpus_stats,
            timeout_seconds=5,
        )
        result = tool.run_axis(spec, {})
        self.assertEqual(result.verdict, tool.VERDICT_MISSING)
        self.assertTrue(result.error)

    def test_timeout_marks_axis_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "stub-sleep.py"
            target.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import time
                    time.sleep(10)
                    """
                ),
                encoding="utf-8",
            )
            target.chmod(0o755)
            spec = tool.AxisSpec(
                name="corpus",
                description="stub-sleep",
                argv_builder=lambda ctx, _t=target: [sys.executable, str(_t)],
                result_parser=tool._parse_corpus_stats,
                timeout_seconds=1,
            )
            result = tool.run_axis(spec, {})
            self.assertEqual(result.verdict, tool.VERDICT_ERROR)
            self.assertIn("timeout", result.summary)

    def test_garbage_stdout_marks_axis_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "stub-garbage.py"
            _write_stub(target, stdout="not-json garbage <<<\n", exit_code=0)
            spec = _stub_axis("corpus", target, tool._parse_corpus_stats)
            result = tool.run_axis(spec, {})
            self.assertEqual(result.verdict, tool.VERDICT_ERROR)
            self.assertIn("json decode", result.summary)

    def test_axis_filter_restricts_to_subset(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            specs = _all_pass_specs(Path(td))
            results = tool.run_dashboard(
                axes=specs, ctx={}, only={"corpus", "mcp-smoke"}
            )
            self.assertEqual([r.name for r in results], ["corpus", "mcp-smoke"])

    def test_envelope_shape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            specs = _all_pass_specs(Path(td))
            results = tool.run_dashboard(axes=specs, ctx={})
            env = tool.render_envelope(results, generated_at="2026-05-16T00:00:00Z")
            self.assertEqual(env["schema"], tool.SCHEMA)
            self.assertEqual(env["generated_at"], "2026-05-16T00:00:00Z")
            self.assertEqual(env["overall_verdict"], tool.VERDICT_PASS)
            self.assertEqual(env["axis_count"], 4)
            self.assertEqual(env["verdict_counts"].get("pass"), 4)
            for axis in env["axes"]:
                self.assertIn("name", axis)
                self.assertIn("verdict", axis)
                self.assertIn("summary", axis)
                self.assertIn("elapsed_seconds", axis)

    def test_human_output_respects_max_lines(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            specs = _all_pass_specs(Path(td))
            results = tool.run_dashboard(axes=specs, ctx={})
            # Default cap (80).
            out_default = tool.render_human(
                results, generated_at="2026-05-16T00:00:00Z", colour_enabled=False
            )
            self.assertLessEqual(len(out_default.splitlines()), 80)
            # Tight cap.
            out_small = tool.render_human(
                results,
                generated_at="2026-05-16T00:00:00Z",
                colour_enabled=False,
                max_lines=5,
            )
            self.assertLessEqual(len(out_small.splitlines()), 5)
            self.assertIn("truncated", out_small)

    def test_determinism_axis_order_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            specs = _all_pass_specs(Path(td))
            r1 = tool.run_dashboard(axes=specs, ctx={})
            r2 = tool.run_dashboard(axes=specs, ctx={})
            self.assertEqual([r.name for r in r1], [r.name for r in r2])
            self.assertEqual(
                [r.name for r in r1],
                ["corpus", "gates", "integrity", "mcp-smoke"],
            )


# ---------------------------------------------------------------------------
# CLI smoke tests via main().
# ---------------------------------------------------------------------------


class CLITests(unittest.TestCase):
    def test_strict_returns_nonzero_on_fail(self) -> None:
        # Build a fail-only dashboard by swapping the real registry temporarily.
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            fail_target = tmpdir / "stub-fail.py"
            _write_stub(fail_target, stdout=json.dumps(_FAIL_GATES_ENV), exit_code=0)
            specs = [_stub_axis("gates", fail_target, tool._parse_gates_status)]
            saved = list(tool.HACKERMAN_DASHBOARD_AXES)
            tool.HACKERMAN_DASHBOARD_AXES.clear()
            tool.HACKERMAN_DASHBOARD_AXES.extend(specs)
            try:
                rc = tool.main(["--strict", "--no-color", "--json"])
                self.assertEqual(rc, 1)
            finally:
                tool.HACKERMAN_DASHBOARD_AXES.clear()
                tool.HACKERMAN_DASHBOARD_AXES.extend(saved)

    def test_unknown_axis_rejected(self) -> None:
        rc = tool.main(["--axis", "no-such-axis", "--json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
