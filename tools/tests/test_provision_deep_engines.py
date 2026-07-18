#!/usr/bin/env python3
"""Hermetic tests for tools/provision-deep-engines.sh and the shared
tools/lib/deep-engine-resolve.sh resolver.

W5-D1 lane. These tests are OFFLINE-SAFE: they never invoke a real
install (no --engine flag is ever passed). They exercise --check mode,
the resolution-order contract, and the runner integration. A real
network install is out of scope for CI.
"""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROVISION = ROOT / "tools" / "provision-deep-engines.sh"
RESOLVER = ROOT / "tools" / "lib" / "deep-engine-resolve.sh"
BIN_DIR = ROOT / "tools" / "deep-engine-bin"


def write_fake_engine(path: Path, version: str) -> None:
    """Write a fake executable that answers --version like a real engine."""
    path.write_text(
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            if [ "$1" = "--version" ]; then echo "{version}"; fi
            exit 0
            """
        ),
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class ProvisionScriptShapeTest(unittest.TestCase):
    def test_script_and_resolver_exist_and_are_executable(self) -> None:
        for p in (PROVISION, RESOLVER):
            self.assertTrue(p.exists(), f"missing {p}")
        self.assertTrue(
            os.access(PROVISION, os.X_OK), "provision script not executable"
        )

    def test_bin_dir_committed_skeleton(self) -> None:
        # The bin dir ships only README + .gitignore; binaries are never
        # committed.
        self.assertTrue((BIN_DIR / ".gitignore").exists())
        self.assertTrue((BIN_DIR / "README.md").exists())

    def test_pinned_versions_present(self) -> None:
        text = PROVISION.read_text(encoding="utf-8")
        for var in ("HALMOS_VERSION=", "MEDUSA_VERSION=", "ECHIDNA_VERSION="):
            self.assertIn(var, text, f"version pin {var} missing")


class CheckModeOfflineTest(unittest.TestCase):
    """--check must run fully offline and report per-engine status."""

    def test_check_reports_missing_when_unprovisioned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            empty_bin = Path(td) / "deep-engine-bin"
            empty_bin.mkdir()
            env = os.environ.copy()
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(empty_bin)
            # Minimal PATH so no system halmos/medusa/echidna leaks in.
            env["PATH"] = "/usr/bin:/bin"
            proc = subprocess.run(
                ["bash", str(PROVISION), "--check"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            # --check exits 1 when an engine is missing; that is expected.
            self.assertIn("halmos: MISSING", proc.stdout)
            self.assertIn("medusa: MISSING", proc.stdout)
            self.assertIn("echidna: MISSING", proc.stdout)
            self.assertEqual(proc.returncode, 1)

    def test_check_reports_available_when_provisioned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bin_dir = Path(td) / "deep-engine-bin"
            bin_dir.mkdir()
            for engine, ver in (
                ("halmos", "halmos 0.2.4"),
                ("medusa", "medusa 1.0.0"),
                ("echidna", "echidna 2.2.5"),
            ):
                write_fake_engine(bin_dir / engine, ver)
            env = os.environ.copy()
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(bin_dir)
            env["PATH"] = "/usr/bin:/bin"
            proc = subprocess.run(
                ["bash", str(PROVISION), "--check"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("halmos: AVAILABLE", proc.stdout)
            self.assertIn("source=provisioned", proc.stdout)
            self.assertIn("medusa: AVAILABLE", proc.stdout)
            self.assertIn("echidna: AVAILABLE", proc.stdout)


class ResolverOrderTest(unittest.TestCase):
    """The resolver must honour env-override > provisioned > PATH."""

    def _resolve(self, engine: str, env: dict) -> tuple[str, str]:
        script = (
            f'. "{RESOLVER}"; '
            f'if resolve_deep_engine {engine}; then '
            f'echo "$DEEP_ENGINE_SOURCE $DEEP_ENGINE_BIN"; '
            f'else echo "none"; fi'
        )
        proc = subprocess.run(
            ["bash", "-c", script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout.strip()

    def test_provisioned_beats_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / "deep-engine-bin"
            bin_dir.mkdir()
            write_fake_engine(bin_dir / "halmos", "halmos prov")
            path_dir = root / "pathbin"
            path_dir.mkdir()
            write_fake_engine(path_dir / "halmos", "halmos path")
            env = os.environ.copy()
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(bin_dir)
            env["PATH"] = f"{path_dir}:/usr/bin:/bin"
            rc, out = self._resolve("halmos", env)
            self.assertEqual(rc, 0)
            self.assertTrue(out.startswith("provisioned"), out)

    def test_env_override_beats_provisioned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / "deep-engine-bin"
            bin_dir.mkdir()
            write_fake_engine(bin_dir / "medusa", "medusa prov")
            override = root / "custom-medusa"
            write_fake_engine(override, "medusa override")
            env = os.environ.copy()
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(bin_dir)
            env["AUDITOOOR_DEEP_BIN_MEDUSA"] = str(override)
            env["PATH"] = "/usr/bin:/bin"
            rc, out = self._resolve("medusa", env)
            self.assertEqual(rc, 0)
            self.assertTrue(out.startswith("env-override"), out)

    def test_missing_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bin_dir = Path(td) / "deep-engine-bin"
            bin_dir.mkdir()
            env = os.environ.copy()
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(bin_dir)
            env["PATH"] = "/usr/bin:/bin"
            _rc, out = self._resolve("echidna", env)
            # resolve_deep_engine returns non-zero internally; the test
            # wrapper's `else echo none` branch confirms that path fired.
            self.assertEqual(out, "none")


class RunnerIntegrationTest(unittest.TestCase):
    """The runners must USE a provisioned binary and skip gracefully
    when none is present (no regression)."""

    def _make_workspace(self, root: Path) -> Path:
        ws = root / "ws"
        (ws / ".auditooor").mkdir(parents=True)
        return ws

    def test_halmos_runner_uses_provisioned_binary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = self._make_workspace(root)
            bin_dir = root / "deep-engine-bin"
            bin_dir.mkdir()
            write_fake_engine(bin_dir / "halmos", "halmos 0.2.4")
            env = os.environ.copy()
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(bin_dir)
            env["PATH"] = "/usr/bin:/bin"
            proc = subprocess.run(
                ["bash", str(ROOT / "tools" / "halmos-runner.sh"), str(ws)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            artifact = ws / ".auditooor" / "halmos" / "artifact.json"
            self.assertTrue(artifact.exists())
            import json

            data = json.loads(artifact.read_text(encoding="utf-8"))
            # The provisioned fake engine exits 0 -> status ok, invoked true.
            self.assertEqual(data["status"], "ok")
            self.assertTrue(data["invoked"])
            self.assertEqual(data["tool"]["path"], str(bin_dir / "halmos"))

    def test_halmos_runner_skips_gracefully_when_unprovisioned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = self._make_workspace(root)
            empty = root / "deep-engine-bin"
            empty.mkdir()
            env = os.environ.copy()
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(empty)
            env["PATH"] = "/usr/bin:/bin"
            proc = subprocess.run(
                ["bash", str(ROOT / "tools" / "halmos-runner.sh"), str(ws)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            # No regression: still exits 0 with a tool-unavailable artifact.
            self.assertEqual(proc.returncode, 0, proc.stderr)
            import json

            data = json.loads(
                (ws / ".auditooor" / "halmos" / "artifact.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(data["status"], "tool-unavailable")
            self.assertFalse(data["invoked"])


if __name__ == "__main__":
    unittest.main()
