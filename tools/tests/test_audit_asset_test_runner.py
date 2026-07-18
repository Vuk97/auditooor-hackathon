from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit-asset-test-runner.py"


def _import():
    spec = importlib.util.spec_from_file_location("audit_asset_test_runner_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _init_repo(root: Path) -> Path:
    repo = root / "asset"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True)
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / ".keep").write_text("tracked\n", encoding="utf-8")
    (repo / "Cargo.toml").write_text("[package]\nname = \"asset\"\nversion = \"0.1.0\"\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return repo


def _source(root: Path, content: str = "borrowed test\n") -> Path:
    path = root / "source-test.rs"
    path.write_text(content, encoding="utf-8")
    return path


def _manifest(capture: Path) -> dict:
    return json.loads((capture / "audit_asset_test_runner_manifest.json").read_text(encoding="utf-8"))


def _status(repo: Path) -> str:
    return _git(repo, "status", "--porcelain=v1", "--untracked-files=all").stdout


class AuditAssetTestRunnerTests(unittest.TestCase):
    def test_dry_run_writes_manifest_without_mutating_asset(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _init_repo(root)
            source = _source(root)
            capture = root / "capture"

            rc = mod.main(
                [
                    "--asset",
                    str(repo),
                    "--insert",
                    str(source),
                    "--target",
                    "tests/borrowed.rs",
                    "--command",
                    "test -f tests/borrowed.rs",
                    "--capture",
                    str(capture),
                ]
            )

            self.assertEqual(rc, 0)
            self.assertFalse((repo / "tests" / "borrowed.rs").exists())
            self.assertEqual(_status(repo), "")
            payload = _manifest(capture)
            self.assertEqual(payload["schema"], "auditooor.audit_asset_test_runner.v1")
            self.assertEqual(payload["mode"], "dry_run")
            self.assertEqual(payload["status"], "dry_run")
            self.assertEqual(payload["commands"][0]["status"], "planned")

    def test_execute_success_captures_output_and_reverts_new_target(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _init_repo(root)
            source = _source(root, "hello from inserted test\n")
            capture = root / "capture"

            rc = mod.main(
                [
                    "--asset",
                    str(repo),
                    "--insert",
                    str(source),
                    "--target",
                    "tests/borrowed.rs",
                    "--command",
                    "python3 -c 'from pathlib import Path; print(Path(\"tests/borrowed.rs\").read_text())'",
                    "--capture",
                    str(capture),
                    "--execute",
                ]
            )

            self.assertEqual(rc, 0)
            self.assertFalse((repo / "tests" / "borrowed.rs").exists())
            self.assertEqual(_status(repo), "")
            payload = _manifest(capture)
            self.assertEqual(payload["status"], "passed_reverted")
            self.assertEqual(payload["commands"][0]["status"], "passed")
            self.assertEqual(payload["commands"][0]["returncode"], 0)
            stdout = Path(payload["commands"][0]["stdout_path"]).read_text(encoding="utf-8")
            self.assertIn("hello from inserted test", stdout)
            self.assertEqual(payload["restoration"]["method"], "unlink_new_file")
            self.assertTrue(payload["restoration"]["final_clean"])

    def test_command_failure_still_reverts(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _init_repo(root)
            source = _source(root)
            capture = root / "capture"

            rc = mod.main(
                [
                    "--asset",
                    str(repo),
                    "--insert",
                    str(source),
                    "--target",
                    "tests/borrowed.rs",
                    "--command",
                    "python3 -c 'import sys; print(\"failing\"); sys.exit(7)'",
                    "--capture",
                    str(capture),
                    "--execute",
                ]
            )

            self.assertEqual(rc, 1)
            self.assertFalse((repo / "tests" / "borrowed.rs").exists())
            self.assertEqual(_status(repo), "")
            payload = _manifest(capture)
            self.assertEqual(payload["status"], "command_failed_reverted")
            self.assertEqual(payload["commands"][0]["status"], "failed")
            self.assertEqual(payload["commands"][0]["returncode"], 7)
            stdout = Path(payload["commands"][0]["stdout_path"]).read_text(encoding="utf-8")
            self.assertIn("failing", stdout)
            self.assertTrue(payload["restoration"]["final_clean"])

    def test_preexisting_dirty_asset_blocks_before_mutation(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _init_repo(root)
            source = _source(root)
            capture = root / "capture"
            (repo / "DIRTY.txt").write_text("dirty\n", encoding="utf-8")

            rc = mod.main(
                [
                    "--asset",
                    str(repo),
                    "--insert",
                    str(source),
                    "--target",
                    "tests/borrowed.rs",
                    "--command",
                    "test -f tests/borrowed.rs",
                    "--capture",
                    str(capture),
                    "--execute",
                ]
            )

            self.assertEqual(rc, 1)
            self.assertFalse((repo / "tests" / "borrowed.rs").exists())
            self.assertIn("DIRTY.txt", _status(repo))
            payload = _manifest(capture)
            self.assertEqual(payload["status"], "blocked")
            self.assertIn("pre-run git status is dirty", payload["error"])
            self.assertFalse(payload["restoration"]["attempted"])


if __name__ == "__main__":
    unittest.main()
