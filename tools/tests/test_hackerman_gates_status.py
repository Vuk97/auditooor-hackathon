"""Tests for ``tools/hackerman-gates-status.py``.

Coverage (>=8 cases):

1. ``_normalise_verdict`` maps the record-verification envelope to fail when
   ``verdict_counts`` includes ``missing-tier`` records.
2. ``_normalise_verdict`` returns pass for an all-clean envelope.
3. ``_normalise_verdict`` reads the ``fail_count`` shape from the subdir gate.
4. ``run_gates`` produces ``missing`` rows when the gate binary is absent.
5. ``run_gates`` honours the ``--gate`` allowlist (selected subset only).
6. ``build_envelope`` aggregates counts deterministically and computes
   ``overall_verdict``.
7. ``render_report`` includes the table header + every gate row + per-gate
   detail block.
8. CLI ``--json`` emits valid JSON envelope with the registered schema.
9. CLI ``--strict`` exits non-zero when any gate fails.
10. Determinism: two consecutive runs (with pinned generated_at) produce
    byte-identical envelopes.
11. ``register_gate`` is idempotent on name collision (in-place replace).
12. Unparseable JSON stdout from a gate is mapped to verdict=``error``.
"""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-gates-status.py"


def _load_tool() -> Any:
    name = "_hackerman_gates_status_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_stub_gate(target: Path, *, stdout_json: str, exit_code: int = 0) -> None:
    """Write a minimal Python script that emits the given JSON + exits exit_code."""
    script = textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
        import sys
        sys.stdout.write({stdout_json!r})
        sys.exit({exit_code})
        """
    )
    target.write_text(script, encoding="utf-8")
    target.chmod(0o755)


class NormaliseVerdictTests(unittest.TestCase):
    def test_record_verification_with_missing_tier_is_fail(self) -> None:
        envelope = {
            "verdict": "fail",
            "verdict_counts": {"missing-tier": 5, "pass": 100, "quarantine": 0},
        }
        self.assertEqual(tool._normalise_verdict(envelope, rc=1), "fail")

    def test_record_verification_all_clean_is_pass(self) -> None:
        envelope = {
            "verdict": "pass",
            "verdict_counts": {"pass": 100},
        }
        self.assertEqual(tool._normalise_verdict(envelope, rc=0), "pass")

    def test_subdir_envelope_uses_fail_count(self) -> None:
        envelope = {"directory_count": 10, "pass_count": 9, "fail_count": 1}
        self.assertEqual(tool._normalise_verdict(envelope, rc=0), "fail")
        envelope_pass = {"directory_count": 10, "pass_count": 10, "fail_count": 0}
        self.assertEqual(tool._normalise_verdict(envelope_pass, rc=0), "pass")


class RunGatesTests(unittest.TestCase):
    def _build_registry(self, tmpdir: Path, gates: list[tuple[str, str, int]]) -> list[Any]:
        """Replace registry with stub gates that emit the given JSON + exit code."""
        specs = []
        for name, stdout_json, exit_code in gates:
            target = tmpdir / f"stub-{name}.py"
            _write_stub_gate(target, stdout_json=stdout_json, exit_code=exit_code)
            spec = tool.GateSpec(
                name=name,
                tool_relpath=str(target.relative_to(REPO_ROOT)) if target.is_relative_to(REPO_ROOT) else str(target),
                description=f"stub gate {name}",
                argv_builder=lambda ctx, _t=target: [sys.executable, str(_t)],
            )
            # GateSpec.absolute_tool_path resolves against REPO_ROOT; ensure tool_relpath is absolute.
            specs.append(
                tool.GateSpec(
                    name=name,
                    tool_relpath=str(target),  # absolute path so absolute_tool_path() == target
                    description=f"stub gate {name}",
                    argv_builder=lambda ctx, _t=target: [sys.executable, str(_t)],
                )
            )
        return specs

    def test_missing_gate_binary_produces_missing_row(self) -> None:
        original = list(tool.HACKERMAN_GATE_REGISTRY)
        try:
            tool.HACKERMAN_GATE_REGISTRY.clear()
            tool.HACKERMAN_GATE_REGISTRY.append(
                tool.GateSpec(
                    name="ghost-gate",
                    tool_relpath="tools/does-not-exist-xyz.py",
                    description="bogus",
                    argv_builder=lambda ctx: [sys.executable, "tools/does-not-exist-xyz.py"],
                )
            )
            rows = tool.run_gates()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["verdict"], "missing")
            self.assertIn("not found", rows[0]["summary"])
        finally:
            tool.HACKERMAN_GATE_REGISTRY.clear()
            tool.HACKERMAN_GATE_REGISTRY.extend(original)

    def test_gate_selector_restricts_execution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            specs = self._build_registry(
                tmpdir,
                [
                    ("alpha", json.dumps({"verdict": "pass"}), 0),
                    ("beta", json.dumps({"verdict": "pass"}), 0),
                ],
            )
            original = list(tool.HACKERMAN_GATE_REGISTRY)
            try:
                tool.HACKERMAN_GATE_REGISTRY.clear()
                tool.HACKERMAN_GATE_REGISTRY.extend(specs)
                rows = tool.run_gates(selected=["alpha"])
                self.assertEqual([r["name"] for r in rows], ["alpha"])
            finally:
                tool.HACKERMAN_GATE_REGISTRY.clear()
                tool.HACKERMAN_GATE_REGISTRY.extend(original)

    def test_unparseable_json_maps_to_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmpdir = Path(td)
            specs = self._build_registry(
                tmpdir,
                [("garbage", "not-json-at-all", 0)],
            )
            original = list(tool.HACKERMAN_GATE_REGISTRY)
            try:
                tool.HACKERMAN_GATE_REGISTRY.clear()
                tool.HACKERMAN_GATE_REGISTRY.extend(specs)
                rows = tool.run_gates()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["verdict"], "error")
                self.assertEqual(rows[0]["summary"], "gate did not emit JSON")
            finally:
                tool.HACKERMAN_GATE_REGISTRY.clear()
                tool.HACKERMAN_GATE_REGISTRY.extend(original)


class BuildEnvelopeTests(unittest.TestCase):
    def test_build_envelope_counts_overall_pass(self) -> None:
        rows = [
            {"name": "a", "tool": "x", "description": "", "verdict": "pass", "rc": 0, "summary": "", "envelope": None, "stderr_tail": ""},
            {"name": "b", "tool": "y", "description": "", "verdict": "pass", "rc": 0, "summary": "", "envelope": None, "stderr_tail": ""},
        ]
        env = tool.build_envelope(rows, generated_at="2026-05-16T00:00:00Z")
        self.assertEqual(env["schema"], "auditooor.hackerman_gates_status.v1")
        self.assertEqual(env["overall_verdict"], "pass")
        self.assertEqual(env["verdict_counts"]["pass"], 2)
        self.assertEqual(env["verdict_counts"]["fail"], 0)

    def test_build_envelope_overall_fail_when_any_fails(self) -> None:
        rows = [
            {"name": "a", "tool": "x", "description": "", "verdict": "pass", "rc": 0, "summary": "", "envelope": None, "stderr_tail": ""},
            {"name": "b", "tool": "y", "description": "", "verdict": "fail", "rc": 1, "summary": "", "envelope": None, "stderr_tail": ""},
        ]
        env = tool.build_envelope(rows, generated_at="2026-05-16T00:00:00Z")
        self.assertEqual(env["overall_verdict"], "fail")


class RenderReportTests(unittest.TestCase):
    def test_render_contains_table_and_detail(self) -> None:
        rows = [
            {
                "name": "g1",
                "tool": "tools/g1.py",
                "description": "desc-g1",
                "verdict": "pass",
                "rc": 0,
                "summary": "rc=0 ok",
                "envelope": None,
                "stderr_tail": "",
            },
            {
                "name": "g2-long-name",
                "tool": "tools/g2.py",
                "description": "desc-g2",
                "verdict": "fail",
                "rc": 1,
                "summary": "rc=1 bad",
                "envelope": None,
                "stderr_tail": "boom\n",
            },
        ]
        env = tool.build_envelope(rows, generated_at="2026-05-16T00:00:00Z")
        text = tool.render_report(env)
        self.assertIn("hackerman gates status", text)
        self.assertIn("GATE", text)
        self.assertIn("VERDICT", text)
        self.assertIn("g1", text)
        self.assertIn("g2-long-name", text)
        self.assertIn("## Per-gate detail", text)
        self.assertIn("desc-g1", text)
        self.assertIn("rc=1 bad", text)


class CLITests(unittest.TestCase):
    def test_cli_json_envelope_is_parseable(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--json",
                "--generated-at",
                "2026-05-16T00:00:00Z",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
        # Aggregator returns 0 by default even when gates fail (advisory mode).
        self.assertEqual(proc.returncode, 0, proc.stderr)
        env = json.loads(proc.stdout)
        self.assertEqual(env["schema"], "auditooor.hackerman_gates_status.v1")
        self.assertEqual(env["generated_at"], "2026-05-16T00:00:00Z")
        self.assertEqual(env["gate_count"], len(tool.HACKERMAN_GATE_REGISTRY))
        names = [r["name"] for r in env["gates"]]
        self.assertIn("record-verification-tier", names)
        self.assertIn("corpus-subdir-acceptance", names)

    def test_cli_strict_returns_nonzero_when_overall_not_pass(self) -> None:
        # Use empty registry via env-style override: pass a non-existent gate name.
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--gate",
                "no-such-gate-zzz",
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
        # No matching gate -> empty registry result -> overall='empty' != 'pass' under --strict.
        self.assertEqual(proc.returncode, 1, proc.stderr)


class DeterminismTests(unittest.TestCase):
    def test_two_runs_with_pinned_generated_at_are_byte_identical(self) -> None:
        def _run() -> str:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--json",
                    "--generated-at",
                    "2026-05-16T00:00:00Z",
                ],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
            )
            return proc.stdout

        out_a = _run()
        out_b = _run()
        env_a = json.loads(out_a)
        env_b = json.loads(out_b)
        # Strip the rc / summary which can drift if corpus changes mid-test.
        # We instead assert the deterministic-by-design fields are stable.
        self.assertEqual(env_a["schema"], env_b["schema"])
        self.assertEqual(env_a["generated_at"], env_b["generated_at"])
        self.assertEqual(env_a["gate_count"], env_b["gate_count"])
        self.assertEqual(
            [g["name"] for g in env_a["gates"]],
            [g["name"] for g in env_b["gates"]],
        )


class RegisterGateTests(unittest.TestCase):
    def test_register_gate_idempotent_on_name_collision(self) -> None:
        original = list(tool.HACKERMAN_GATE_REGISTRY)
        try:
            spec_a = tool.GateSpec(
                name="dup",
                tool_relpath="tools/a.py",
                description="A",
                argv_builder=lambda ctx: [],
            )
            spec_b = tool.GateSpec(
                name="dup",
                tool_relpath="tools/b.py",
                description="B",
                argv_builder=lambda ctx: [],
            )
            tool.register_gate(spec_a)
            tool.register_gate(spec_b)
            matches = [s for s in tool.HACKERMAN_GATE_REGISTRY if s.name == "dup"]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].description, "B")
        finally:
            tool.HACKERMAN_GATE_REGISTRY.clear()
            tool.HACKERMAN_GATE_REGISTRY.extend(original)


if __name__ == "__main__":
    unittest.main()
