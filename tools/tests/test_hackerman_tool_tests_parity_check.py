"""Tests for tools/hackerman-tool-tests-parity-check.py.

Wave-1 hackerman capability lift (PR #726). Covers tool/test name mapping,
discovery, paired/missing/orphan verdicts, --strict exit-code, and JSON/text
rendering. Uses an isolated tmp directory so tests do not depend on the live
tool/test layout in the repo.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "hackerman-tool-tests-parity-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "hackerman_tool_tests_parity_check", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()


def _make_layout(
    root: Path,
    tools: list[str],
    tests: list[str],
) -> tuple[Path, Path]:
    tools_dir = root / "tools"
    tests_dir = root / "tools" / "tests"
    tools_dir.mkdir(parents=True, exist_ok=True)
    tests_dir.mkdir(parents=True, exist_ok=True)
    for name in tools:
        (tools_dir / name).write_text("#!/usr/bin/env python3\n")
    for name in tests:
        (tests_dir / name).write_text('"""test"""\n')
    return tools_dir, tests_dir


class NameMappingTest(unittest.TestCase):
    def test_tool_to_test_simple(self) -> None:
        self.assertEqual(
            MODULE.tool_to_test_name("hackerman-foo.py"),
            "test_hackerman_foo.py",
        )

    def test_tool_to_test_etl_from(self) -> None:
        self.assertEqual(
            MODULE.tool_to_test_name("hackerman-etl-from-bar.py"),
            "test_hackerman_etl_from_bar.py",
        )

    def test_tool_to_test_preserves_dots(self) -> None:
        # tools with literal '.' in the stem (e.g. v1.1) do not collapse.
        self.assertEqual(
            MODULE.tool_to_test_name("hackerman-schema-v1-to-v1.1-migrator.py"),
            "test_hackerman_schema_v1_to_v1.1_migrator.py",
        )

    def test_test_to_tool_inverse(self) -> None:
        self.assertEqual(
            MODULE.test_to_tool_name("test_hackerman_foo.py"),
            "hackerman-foo.py",
        )


class DiscoveryTest(unittest.TestCase):
    def test_discover_tools_picks_only_hackerman(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tools_dir, _ = _make_layout(
                Path(tmp),
                tools=[
                    "hackerman-a.py",
                    "hackerman-etl-from-b.py",
                    "not-a-hackerman-tool.py",
                ],
                tests=[],
            )
            found = MODULE.discover_tools(tools_dir)
            names = [p.name for p in found]
            self.assertIn("hackerman-a.py", names)
            self.assertIn("hackerman-etl-from-b.py", names)
            self.assertNotIn("not-a-hackerman-tool.py", names)

    def test_discover_tests_picks_only_test_hackerman(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, tests_dir = _make_layout(
                Path(tmp),
                tools=[],
                tests=[
                    "test_hackerman_a.py",
                    "test_other.py",
                ],
            )
            found = MODULE.discover_tests(tests_dir)
            names = [p.name for p in found]
            self.assertIn("test_hackerman_a.py", names)
            self.assertNotIn("test_other.py", names)


class ReportTest(unittest.TestCase):
    def test_paired_and_missing_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tools_dir, tests_dir = _make_layout(
                Path(tmp),
                tools=["hackerman-paired.py", "hackerman-lonely.py"],
                tests=["test_hackerman_paired.py"],
            )
            report = MODULE.build_report(tools_dir, tests_dir)
            verdicts = {r["tool"]: r["verdict"] for r in report["tools"]}
            self.assertEqual(verdicts["hackerman-paired.py"], "paired")
            self.assertEqual(verdicts["hackerman-lonely.py"], "missing-test")
            self.assertEqual(report["summary"]["paired"], 1)
            self.assertEqual(report["summary"]["missing_test"], 1)

    def test_orphan_test_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tools_dir, tests_dir = _make_layout(
                Path(tmp),
                tools=["hackerman-paired.py"],
                tests=[
                    "test_hackerman_paired.py",
                    "test_hackerman_ghost.py",
                ],
            )
            report = MODULE.build_report(tools_dir, tests_dir)
            self.assertEqual(report["summary"]["orphan_test"], 1)
            self.assertEqual(report["orphan_tests"][0]["test"], "test_hackerman_ghost.py")

    def test_empty_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tools_dir, tests_dir = _make_layout(Path(tmp), tools=[], tests=[])
            report = MODULE.build_report(tools_dir, tests_dir)
            self.assertEqual(report["summary"]["tool_count"], 0)
            self.assertEqual(report["summary"]["test_count"], 0)
            self.assertEqual(report["summary"]["paired"], 0)
            self.assertEqual(report["summary"]["missing_test"], 0)
            self.assertEqual(report["summary"]["orphan_test"], 0)


class CliTest(unittest.TestCase):
    def _run(self, args: list[str], cwd: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )

    def test_strict_exits_1_on_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools_dir, tests_dir = _make_layout(
                root,
                tools=["hackerman-needs-test.py"],
                tests=[],
            )
            r = self._run(
                [
                    "--tools-dir",
                    str(tools_dir),
                    "--tests-dir",
                    str(tests_dir),
                    "--strict",
                ],
                cwd=root,
            )
            self.assertEqual(r.returncode, 1, msg=r.stdout + r.stderr)
            self.assertIn("missing-test", r.stdout)

    def test_default_exit_0_even_with_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools_dir, tests_dir = _make_layout(
                root,
                tools=["hackerman-needs-test.py"],
                tests=[],
            )
            r = self._run(
                [
                    "--tools-dir",
                    str(tools_dir),
                    "--tests-dir",
                    str(tests_dir),
                ],
                cwd=root,
            )
            self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)

    def test_json_output_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools_dir, tests_dir = _make_layout(
                root,
                tools=["hackerman-paired.py"],
                tests=["test_hackerman_paired.py"],
            )
            r = self._run(
                [
                    "--tools-dir",
                    str(tools_dir),
                    "--tests-dir",
                    str(tests_dir),
                    "--format",
                    "json",
                ],
                cwd=root,
            )
            self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)
            payload = json.loads(r.stdout)
            self.assertEqual(payload["summary"]["tool_count"], 1)
            self.assertEqual(payload["summary"]["paired"], 1)
            self.assertEqual(payload["summary"]["missing_test"], 0)
            self.assertIn("tools", payload)
            self.assertIn("orphan_tests", payload)


class LiveRepoTest(unittest.TestCase):
    """Smoke test against the real repo layout - the tool must at minimum run."""

    def test_runs_against_repo(self) -> None:
        report = MODULE.build_report(
            REPO_ROOT / "tools",
            REPO_ROOT / "tools" / "tests",
        )
        # Tool count must include the parity-check tool itself.
        self.assertGreaterEqual(report["summary"]["tool_count"], 1)
        tool_names = {r["tool"] for r in report["tools"]}
        self.assertIn("hackerman-tool-tests-parity-check.py", tool_names)


if __name__ == "__main__":
    unittest.main()
