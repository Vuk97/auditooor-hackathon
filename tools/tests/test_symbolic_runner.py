#!/usr/bin/env python3
"""PR 109 — symbolic-runner smoke tests.

No network. No real halmos/kontrol install. Each test PATH-shadows the
halmos/kontrol binary with a mocked shell script, mirroring the pattern
used by test_fuzz_runner.py (PR 107) and test_fork_replay_cli.py.

Scope: PR 109 is narrow — A-AUTH only, advisory only.
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
TOOL = ROOT / "tools" / "symbolic-runner.sh"


def write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip())
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _has_real_timeout() -> bool:
    for cand in ("timeout", "gtimeout"):
        for base in ("/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"):
            if Path(base, cand).exists():
                return True
    return False


_SHIM_TIMEOUT = r"""#!/usr/bin/env python3
# Portable `timeout` replacement for symbolic-runner tests only.
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


def install_timeout_shim(fake_bin: Path) -> None:
    if _has_real_timeout():
        return
    p = fake_bin / "timeout"
    p.write_text(_SHIM_TIMEOUT)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)


def minimal_path_with(fake_bin: Path) -> str:
    """PATH containing fake_bin + essentials for date/awk/grep/python3.

    halmos/kontrol are NOT reachable unless placed in `fake_bin`.

    PR 212 note: see the matching comment in tools/tests/test_fuzz_runner.py.
    Homebrew/usr-local are skipped when they'd shadow `halmos` or `kontrol`
    so the `no engine present` test can actually reach the SKIPPED path on
    hosts that have halmos installed system-wide.
    """
    essentials = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    for extra in ("/opt/homebrew/bin", "/usr/local/bin"):
        bl = Path(extra)
        if (bl / "halmos").exists() or (bl / "kontrol").exists():
            continue
        essentials.append(extra)
    return os.pathsep.join([str(fake_bin), *essentials])


class SymbolicRunnerTest(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. Mocked halmos returns no-counterexample (clean pass).
    # ------------------------------------------------------------------
    def test_mocked_halmos_no_counterexample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"; workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking halmos. Scaffold a minimal
            # one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            write_executable(
                fake_bin / "halmos",
                """
                #!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *)         exit 0 ;;
                esac
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--contract", "Vault",
                 "--timeout", "5",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((out_dir / "status.txt").read_text().strip(),
                             "no-counterexample")
            self.assertEqual((out_dir / "engine.txt").read_text().strip(), "halmos")
            self.assertEqual((out_dir / "angle.txt").read_text().strip(), "A-AUTH")
            self.assertEqual((out_dir / "contract.txt").read_text().strip(), "Vault")
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "no-counterexample")
            self.assertEqual(manifest["engine"], "halmos")
            self.assertEqual(manifest["angle"], "A-AUTH")
            self.assertEqual(manifest["contract"], "Vault")
            self.assertEqual(manifest["timeout_seconds"], 5)
            self.assertIsNone(manifest["counterexample_path"])
            self.assertTrue(manifest["advisory"])
            self.assertEqual(manifest["phase"], "C")
            self.assertEqual(manifest["pr"], 109)

    # ------------------------------------------------------------------
    # 2. Mocked halmos returns counterexample.
    # ------------------------------------------------------------------
    def test_mocked_halmos_counterexample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"; workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking halmos. Scaffold a minimal
            # one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            write_executable(
                fake_bin / "halmos",
                """
                #!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *)
                    printf 'Counterexample:\\n'
                    printf '  msg.sender = 0x1337\\n'
                    printf '  admin      = 0xbeef\\n'
                    printf '  → setOwner() modified owner from non-admin caller\\n'
                    exit 0 ;;
                esac
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--contract", "Vault",
                 "--timeout", "5",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((out_dir / "status.txt").read_text().strip(),
                             "counterexample")
            ce = out_dir / "counterexample.txt"
            self.assertTrue(ce.exists())
            self.assertGreater(ce.stat().st_size, 0)
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "counterexample")
            self.assertEqual(manifest["counterexample_path"], "counterexample.txt")
            self.assertTrue(manifest["advisory"])

    # ------------------------------------------------------------------
    # 3. Mocked halmos times out (sleep > --timeout).
    # ------------------------------------------------------------------
    def test_mocked_halmos_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"; workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking halmos. Scaffold a minimal
            # one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            write_executable(
                fake_bin / "halmos",
                """
                #!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *)         sleep 100 ;;
                esac
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--contract", "Vault",
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
            self.assertTrue(manifest["advisory"])

    # ------------------------------------------------------------------
    # 4. No engine on PATH → SKIPPED, exit 0.
    # ------------------------------------------------------------------
    def test_no_engine_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()  # empty — no halmos/kontrol
            workspace = tmp_path / "ws"; workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking halmos. Scaffold a minimal
            # one so the project-root resolver passes.
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
                 "--contract", "Vault",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(
                "No symbolic engine found",
                proc.stdout + proc.stderr,
            )
            self.assertEqual((out_dir / "engine.txt").read_text().strip(), "SKIPPED")
            self.assertEqual((out_dir / "status.txt").read_text().strip(), "skipped")
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["engine"], "SKIPPED")
            self.assertEqual(manifest["status"], "skipped")
            self.assertTrue(manifest["advisory"])

    # ------------------------------------------------------------------
    # 5. --dry-run: command.txt pre-written, engine NOT invoked (tripwire).
    # ------------------------------------------------------------------
    def test_dry_run_does_not_invoke_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"; workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking halmos. Scaffold a minimal
            # one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"
            tripwire = tmp_path / "tripwire.flag"

            # Tripwire fires only on real invocations (any argv where $1 is not
            # --version), so best-effort `halmos --version` probe is allowed.
            write_executable(
                fake_bin / "halmos",
                f"""
                #!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "halmos 0.0-test" ;;
                  *)         touch "{tripwire}" ;;
                esac
                exit 0
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--contract", "Vault",
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
            self.assertFalse((out_dir / "stdout.log").exists(),
                             "dry-run wrote stdout.log")

    # ------------------------------------------------------------------
    # 6. Missing target with no mining_priorities.json → exits non-zero
    # with a distinct no-target manifest before invoking anything.
    # ------------------------------------------------------------------
    def test_missing_contract_no_autopick_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"; workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking halmos. Scaffold a minimal
            # one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"  # intentionally not created
            tripwire = tmp_path / "tripwire.flag"

            write_executable(
                fake_bin / "halmos",
                f"""
                #!/usr/bin/env bash
                touch "{tripwire}"
                exit 0
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--timeout", "5",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("cannot-run: no-target", proc.stderr)
            self.assertIn("A-AUTH target not provided", proc.stderr)
            # Tripwire must NOT fire — we rejected before any engine probe.
            self.assertFalse(tripwire.exists(),
                             "engine invoked before contract validation")
            # Workspace untouched, explicit out-dir contains structured
            # no-target evidence for callers.
            self.assertFalse((workspace / "symbolic_runs").exists())
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "skipped")
            self.assertEqual(manifest["engine"], "SKIPPED")
            self.assertIn("cannot-run: no-target", manifest["notes"])

    # ------------------------------------------------------------------
    # 7. Explicit --test-contract is a valid symbolic target even when the
    # production --contract was not supplied/autopicked.
    # ------------------------------------------------------------------
    def test_explicit_test_contract_routes_without_production_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"; workspace.mkdir()
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"
            tripwire = tmp_path / "tripwire.flag"

            write_executable(
                fake_bin / "halmos",
                f"""
                #!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "halmos 0.0-test" ;;
                  *)         touch "{tripwire}" ;;
                esac
                exit 0
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--test-contract", "HandWrittenHalmosTest",
                 "--timeout", "5",
                 "--out-dir", str(out_dir),
                 "--dry-run"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(tripwire.exists())
            self.assertEqual((out_dir / "contract.txt").read_text(), "\n")
            self.assertEqual((out_dir / "test_contract.txt").read_text().strip(),
                             "HandWrittenHalmosTest")
            self.assertEqual((out_dir / "engine_contract.txt").read_text().strip(),
                             "HandWrittenHalmosTest")
            self.assertEqual((out_dir / "target_source.txt").read_text().strip(),
                             "explicit-test-contract")
            self.assertIn("--contract HandWrittenHalmosTest",
                          (out_dir / "command.txt").read_text())
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["test_contract"], "HandWrittenHalmosTest")
            self.assertEqual(manifest["engine_contract"], "HandWrittenHalmosTest")

    # ------------------------------------------------------------------
    # 8. Nested Solidity project roots use the project's test dir for
    # Invariant_/Property_ discovery, not the audit workspace root.
    # ------------------------------------------------------------------
    def test_project_root_controls_harness_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"; workspace.mkdir()
            project = workspace / "src" / "solidity-app"
            (project / "halmos-tests").mkdir(parents=True)
            (project / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\ntest = \"halmos-tests\"\n",
                encoding="utf-8",
            )
            (project / "halmos-tests" / "Invariant_NestedVault.t.sol").write_text(
                "pragma solidity ^0.8.20; contract Invariant_NestedVault {}\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            write_executable(
                fake_bin / "halmos",
                """
                #!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *)         exit 0 ;;
                esac
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--contract", "NestedVault",
                 "--project-root", str(project),
                 "--timeout", "5",
                 "--out-dir", str(out_dir),
                 "--dry-run"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((out_dir / "project_root.txt").read_text().strip(),
                             str(project))
            self.assertEqual((out_dir / "test_dir.txt").read_text().strip(),
                             str(project / "halmos-tests"))
            self.assertEqual((out_dir / "engine_contract.txt").read_text().strip(),
                             "Invariant_NestedVault")
            self.assertEqual((out_dir / "target_source.txt").read_text().strip(),
                             "discovered-invariant")

    # ------------------------------------------------------------------
    # 9. Unsupported Foundry cheatcodes are blocked tooling evidence, not
    # generic symbolic "errors". Revert exposed this with vm.copyStorage.
    # ------------------------------------------------------------------
    def test_halmos_unsupported_cheatcode_is_classified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"; workspace.mkdir()
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            write_executable(
                fake_bin / "halmos",
                """
                #!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *)
                    echo "Error: Unsupported cheat code: copyStorage(address,address)" >&2
                    exit 1 ;;
                esac
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--contract", "Vault",
                 "--timeout", "5",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((out_dir / "status.txt").read_text().strip(),
                             "blocked_unsupported_cheatcode")
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "blocked_unsupported_cheatcode")
            self.assertIn("unsupported Foundry cheatcode", manifest["notes"])

    # ------------------------------------------------------------------
    # 10. Bounded/incomplete Halmos runs are not clean proof.
    # ------------------------------------------------------------------
    def test_halmos_incomplete_bound_is_classified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"; fake_bin.mkdir()
            install_timeout_shim(fake_bin)
            workspace = tmp_path / "ws"; workspace.mkdir()
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            write_executable(
                fake_bin / "halmos",
                """
                #!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *)
                    echo "Warning: incomplete execution due to the specified limit" >&2
                    echo "loop unrolling bound reached before full proof" >&2
                    exit 1 ;;
                esac
                """,
            )

            env = os.environ.copy()
            env["PATH"] = minimal_path_with(fake_bin)
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--contract", "Vault",
                 "--timeout", "5",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((out_dir / "status.txt").read_text().strip(),
                             "incomplete_timeout_or_bound")
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "incomplete_timeout_or_bound")
            self.assertIn("exploration limit", manifest["notes"])

    # ------------------------------------------------------------------
    # 11. Unknown angle rejected (post-PR 202: A-AUTH, A-ORACLE, A-REENT
    # are the supported set; anything else is rejected with exit 2 and
    # stderr cites the allowlist). An error manifest IS written to the
    # --out-dir override so downstream consumers can key off status=error.
    # ------------------------------------------------------------------
    def test_non_auth_angle_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "ws"; workspace.mkdir()
            # I13 (#328): the runner now requires a forge project root
            # (foundry.toml) before invoking halmos. Scaffold a minimal
            # one so the project-root resolver passes.
            (workspace / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            out_dir = tmp_path / "out"

            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace),
                 "--engine", "halmos",
                 "--angle", "A-RACE",   # PR 202 keeps A-RACE out of scope.
                 "--contract", "Vault",
                 "--out-dir", str(out_dir)],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("unsupported --angle 'A-RACE'", proc.stderr)
            self.assertIn("A-AUTH|A-ORACLE|A-REENT", proc.stderr)
            # No workspace-local symbolic_runs dir gets created — we only
            # touch the explicit --out-dir for the error manifest.
            self.assertFalse((workspace / "symbolic_runs").exists())
            # Post-PR-202: an error manifest IS written into the explicit
            # --out-dir so downstream consumers can key off manifest.status.
            self.assertTrue((out_dir / "manifest.json").exists())
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "error")
            self.assertEqual(manifest["angle"], "A-RACE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
