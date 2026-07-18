from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "oscript-aa-testkit-runner.py"
SPEC = importlib.util.spec_from_file_location("oscript_aa_testkit_runner", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def make_project(root: Path, name: str, *, installed: bool = True, test_script: str = "mocha") -> Path:
    project = root / "src" / name
    project.mkdir(parents=True)
    (project / "package.json").write_text(
        json.dumps({"name": name, "dependencies": {"aa-testkit": "git+https://example.invalid/aa-testkit"}, "scripts": {"test": test_script}}),
        encoding="utf-8",
    )
    test = project / "test" / "example.test.oscript.js"
    test.parent.mkdir()
    test.write_text("describe('aa', () => {});\n", encoding="utf-8")
    if installed:
        (project / "node_modules" / "aa-testkit").mkdir(parents=True)
    return project


class OscriptAATestkitRunnerTests(unittest.TestCase):
    def test_discovery_requires_declared_and_installed_testkit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = make_project(root, "ready")
            make_project(root, "blocked", installed=False)
            rows = MODULE.discover(root)
        self.assertEqual([row["project"] for row in rows], ["src/blocked", "src/ready"])
        self.assertEqual(rows[0]["status"], "blocked")
        self.assertEqual(rows[1]["status"], "ready")
        self.assertEqual(rows[1]["test_files"][0]["path"], "test/example.test.oscript.js")
        self.assertTrue(ready)

    def test_execute_records_runtime_only_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_project(root, "ready")
            def fake_runner(*args, **kwargs):
                self.assertEqual(args[0], ["npm", "run", "test"])
                self.assertEqual(kwargs["cwd"].resolve(), (root / "src" / "ready").resolve())
                return subprocess.CompletedProcess(args[0], 0, stdout="pass", stderr="")
            receipts = MODULE.execute(root, project="src/ready", runner=fake_runner)
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertEqual(receipt["schema"], MODULE.SCHEMA)
        self.assertEqual(receipt["status"], "passed")
        self.assertTrue(receipt["credit"]["runtime_execution"])
        self.assertFalse(receipt["credit"]["semantic_engine"])
        self.assertFalse(receipt["credit"]["reasoner"])
        self.assertFalse(receipt["credit"]["fuzz"])

    def test_execute_refuses_blocked_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_project(root, "blocked", installed=False)
            with self.assertRaisesRegex(RuntimeError, "not runnable"):
                MODULE.execute(root, project="src/blocked")

    def test_project_selection_cannot_escape_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_project(root, "ready")
            with self.assertRaisesRegex(ValueError, "outside workspace"):
                MODULE._select_project(root, MODULE.discover(root), "../outside")

    def test_cli_returns_nonzero_when_runtime_suite_fails(self) -> None:
        failed = [{"status": "failed"}]
        with mock.patch.object(MODULE, "execute", return_value=failed):
            self.assertEqual(MODULE.main(["--workspace", "/tmp", "--execute"]), 1)

    def test_cli_returns_zero_when_runtime_suite_passes(self) -> None:
        passed = [{"status": "passed"}]
        with mock.patch.object(MODULE, "execute", return_value=passed):
            self.assertEqual(MODULE.main(["--workspace", "/tmp", "--execute"]), 0)


if __name__ == "__main__":
    unittest.main()
