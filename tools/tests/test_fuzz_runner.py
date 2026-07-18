#!/usr/bin/env python3
"""PR 107 — bounded fuzz runner smoke tests.

No network. No real fuzz engine install. Each test PATH-shadows the
medusa/echidna binary with a mocked shell script, following the pattern
used by test_fork_replay_cli.py.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "fuzz-runner.sh"


def write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip())
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _has_real_timeout_on(path_dirs: list[str]) -> bool:
    """Return True if `timeout` or `gtimeout` is resolvable on the given PATH dirs.

    Distinct from host-PATH detection: `minimal_path_with()` deliberately
    strips `/opt/homebrew/bin` / `/usr/local/bin` when they would shadow fake
    engines, which on macOS also strips the only location where GNU
    coreutils' `timeout` lives (it is not shipped in /usr/bin on Darwin).
    The caller passes the exact PATH dirs the subprocess will see, so the
    shim-install decision reflects subprocess reality, not host reality.
    """
    for cand in ("timeout", "gtimeout"):
        for base in path_dirs:
            if Path(base, cand).exists():
                return True
    return False


_SHIM_TIMEOUT = r"""#!/usr/bin/env python3
# Portable `timeout` replacement for fuzz-runner tests only.
# Signature: timeout <N>s <cmd> [args...]
# Exit codes match GNU coreutils: 124 on timeout, otherwise the child exit code.
import os, signal, subprocess, sys

if len(sys.argv) < 3:
    sys.stderr.write("shim-timeout: usage <Ns> <cmd> [args...]\n")
    sys.exit(125)

spec = sys.argv[1]
if spec.endswith("s"):
    spec = spec[:-1]
try:
    seconds = float(spec)
except ValueError:
    sys.stderr.write("shim-timeout: bad duration\n")
    sys.exit(125)

cmd = sys.argv[2:]
p = subprocess.Popen(cmd, start_new_session=True)
try:
    rc = p.wait(timeout=seconds)
    sys.exit(rc)
except subprocess.TimeoutExpired:
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    p.wait()
    sys.exit(124)
"""


def install_timeout_shim(fake_bin: Path, subprocess_path_dirs: list[str] | None = None) -> None:
    """Drop a Python `timeout` shim into fake_bin when the subprocess PATH lacks one.

    The shim is named `timeout` so fuzz-runner.sh finds it first on PATH. It
    mirrors GNU coreutils exit-code discipline (124 on timeout, otherwise the
    child exit code) so tests exercise the same code paths as a real
    `timeout`.

    PR (iter2 T3): previously this gated on host PATH, but on macOS `timeout`
    lives only in `/opt/homebrew/bin`, which `minimal_path_with()` deliberately
    excludes when it would shadow fake engines. That disagreement caused the
    runner's timeout-utility check to abort with exit 3 even though a real
    `timeout` was installed on the host. The decision now follows the exact
    PATH the subprocess will see.
    """
    if subprocess_path_dirs is not None and _has_real_timeout_on(subprocess_path_dirs):
        return
    p = fake_bin / "timeout"
    p.write_text(_SHIM_TIMEOUT)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)


def minimal_path_with(fake_bin: Path) -> str:
    """PATH that contains the fake bin dir plus essentials for date/awk/grep.

    medusa/echidna are NOT reachable unless we placed a fake in `fake_bin`.

    PR 212 note: we previously included `/opt/homebrew/bin` and
    `/usr/local/bin` unconditionally, which meant the "no engine present"
    tests silently picked up a real `medusa`/`echidna` install on the host
    — defeating the test. Those prefixes are now only added when they do
    NOT shadow the engine binaries. Callers that need homebrew/local paths
    for a specific binary should place a mock in `fake_bin` and rely on the
    fake_bin-prefix precedence.
    """
    essentials = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    for extra in ("/opt/homebrew/bin", "/usr/local/bin"):
        bl = Path(extra)
        if (bl / "medusa").exists() or (bl / "echidna").exists():
            continue
        essentials.append(extra)
    return os.pathsep.join([str(fake_bin), *essentials])


class FuzzRunnerTest(unittest.TestCase):
    pass

    # ------------------------------------------------------------------
    # 1. Mocked medusa returns pass.
    # ------------------------------------------------------------------
    def test_mocked_medusa_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"
            fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"
            workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking medusa/echidna. Scaffold a
            # minimal one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            write_executable(
                fake_bin / "medusa",
                """
                #!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "medusa 0.0-test"; exit 0 ;;
                  fuzz)      exit 0 ;;   # no output, clean pass
                  *)         exit 0 ;;
                esac
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "medusa",
                 "--timeout", "5",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((out_dir / "status.txt").read_text().strip(), "pass")
            self.assertEqual((out_dir / "engine.txt").read_text().strip(), "medusa")
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "pass")
            self.assertEqual(manifest["engine"], "medusa")
            self.assertEqual(manifest["timeout_seconds"], 5)
            self.assertIsNone(manifest["counterexample_path"])

    # ------------------------------------------------------------------
    # 2. Mocked medusa returns counterexample.
    # ------------------------------------------------------------------
    def test_mocked_medusa_counterexample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"
            fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"
            workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking medusa/echidna. Scaffold a
            # minimal one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            write_executable(
                fake_bin / "medusa",
                """
                #!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "medusa 0.0-test"; exit 0 ;;
                  fuzz)
                    printf 'Counterexample:\\n'
                    printf 'call sequence: [mint(0x0), redeem(max)]\\n'
                    exit 0 ;;
                  *) exit 0 ;;
                esac
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "medusa",
                 "--timeout", "5",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((out_dir / "status.txt").read_text().strip(), "counterexample")
            seq = out_dir / "failing_sequence.txt"
            self.assertTrue(seq.exists())
            self.assertGreater(seq.stat().st_size, 0)
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "counterexample")
            self.assertEqual(manifest["counterexample_path"], "failing_sequence.txt")

    # ------------------------------------------------------------------
    # 3. Mocked medusa times out.
    # ------------------------------------------------------------------
    def test_mocked_medusa_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"
            fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"
            workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking medusa/echidna. Scaffold a
            # minimal one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            # Fake medusa: sleep only on `fuzz` subcommand. `--version` returns
            # immediately so the runner's best-effort version probe doesn't hang.
            write_executable(
                fake_bin / "medusa",
                """
                #!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "medusa 0.0-test"; exit 0 ;;
                  fuzz)      sleep 100 ;;
                  *)         exit 0 ;;
                esac
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "medusa",
                 "--timeout", "1",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
                timeout=30,
            )
            # Advisory discipline: runner itself exits 0 on engine outcome.
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((out_dir / "status.txt").read_text().strip(), "timeout")
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "timeout")

    # ------------------------------------------------------------------
    # 4. No engine on PATH → SKIPPED.
    # ------------------------------------------------------------------
    def test_no_engine_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"
            fake_bin.mkdir()  # empty — no medusa, no echidna
            # PR 212: the runner refuses to run unbounded when no `timeout` /
            # `gtimeout` is on PATH. macOS ships neither, so install the
            # portable Python shim before asserting the SKIPPED-engine path.
            # Without this, the test failed with exit 3 on macOS even though
            # the engine logic under test was behaving correctly.
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"
            workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking medusa/echidna. Scaffold a
            # minimal one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "auto",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(
                "No fuzz engine found — run install per docs/WORKFLOW.md",
                proc.stdout + proc.stderr,
            )
            self.assertEqual((out_dir / "engine.txt").read_text().strip(), "SKIPPED")
            self.assertEqual((out_dir / "status.txt").read_text().strip(), "skipped")
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["engine"], "SKIPPED")
            self.assertEqual(manifest["status"], "skipped")

    # ------------------------------------------------------------------
    # 5. --dry-run: command.txt is pre-written, engine NOT invoked.
    # ------------------------------------------------------------------
    def test_dry_run_does_not_invoke_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"
            fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"
            workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking medusa/echidna. Scaffold a
            # minimal one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"
            tripwire = tmp_path / "tripwire.flag"

            # Tripwire: if medusa is invoked with `fuzz`, it touches this
            # file. Dry-run must NOT reach `fuzz`. The runner does a
            # best-effort `medusa --version` probe which is NOT a tripwire.
            write_executable(
                fake_bin / "medusa",
                f"""
                #!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "medusa 0.0-test" ;;
                  fuzz)      touch "{tripwire}" ;;
                  *)         : ;;
                esac
                exit 0
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "medusa",
                 "--timeout", "5",
                 "--out-dir", str(out_dir),
                 "--dry-run"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(tripwire.exists(),
                             "dry-run invoked engine (tripwire file exists)")
            cmd_txt = out_dir / "command.txt"
            self.assertTrue(cmd_txt.exists())
            self.assertGreater(cmd_txt.stat().st_size, 0)
            # stdout.log is NOT created on dry-run (engine never ran).
            self.assertFalse((out_dir / "stdout.log").exists(),
                             "dry-run wrote stdout.log")

    # ------------------------------------------------------------------
    # 6. Invalid --engine exits non-zero before touching workspace.
    # ------------------------------------------------------------------
    def test_invalid_engine_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "ws"
            workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking medusa/echidna. Scaffold a
            # minimal one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"  # intentionally not created

            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "foundry",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("invalid --engine", proc.stderr)
            # Workspace must remain untouched: no fuzz_runs/, no manifest.
            self.assertFalse((workspace / "fuzz_runs").exists())
            self.assertFalse((out_dir / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
