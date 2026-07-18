#!/usr/bin/env python3
"""PR 212 — CI preflight smoke tests.

Covers `tools/ci-preflight.sh` and the `tool-availability.sh` helper it
sources. These tests do NOT install or uninstall real binaries; they
simulate missing tools by prepending an empty directory to PATH and
simulate a missing forge with a PATH that excludes the forge install
directory.

Status vocabulary asserted here:
    ✓   present
    ✗   missing
    YES all critical tools present
    NO  at least one critical tool missing

If any of those strings changes, the Makefile `ci-preflight` target and
`.github/workflows/offline-tests.yml` both need to keep lining up.

Truth-audit anchor: `test_missing_forge_fails_preflight` is the
regression test called out in the PR 212 brief. It catches the mistake
of accidentally tagging forge as optional.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "tools" / "ci-preflight.sh"


def _run(env: dict, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(PREFLIGHT)],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def _minimal_essential_path() -> str:
    """A PATH with the minimum tools bash/awk/grep/date need.

    Deliberately excludes foundry's install prefix so `forge` is NOT
    discoverable unless the caller adds it back.
    """
    out = []
    for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if Path(d).exists():
            out.append(d)
    return os.pathsep.join(out)


def _find_forge_dir() -> Path | None:
    p = shutil.which("forge")
    return Path(p).parent if p else None


def _write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip())
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class CiPreflightFormatTest(unittest.TestCase):
    """Format assertions: labels, status glyphs, and summary lines."""

    def test_prints_expected_table_rows(self) -> None:
        proc = _run(os.environ.copy())
        # Preflight MAY exit 0 or 1 here (depends on local state), but the
        # table layout is always printed.
        out = proc.stdout + proc.stderr
        self.assertIn("[ci-preflight]", out)
        for label in (
            "forge:", "cast:", "anvil:",
            "medusa:", "echidna:",
            "halmos:", "mythril:",
            "slither:",
            "jq:", "python3:", "timeout:",
        ):
            self.assertIn(label, out, f"row for {label!r} missing from preflight output")

    def test_emits_narrow_status_vocabulary(self) -> None:
        """No stray status words leak into the preflight report."""
        proc = _run(os.environ.copy())
        out = proc.stdout + proc.stderr
        # Exactly one of the YES/NO banners must appear on its own line.
        yes = re.search(r"^All critical tools present: YES$", out, re.MULTILINE)
        no = re.search(r"^All critical tools present: NO$", out, re.MULTILINE)
        self.assertTrue(bool(yes) ^ bool(no),
                        "preflight must print exactly one YES or NO banner")
        # Banned words — the preflight is planning info, NOT a submission
        # gate, so it must not reuse gate-status vocabulary like PASS/FAIL
        # or INCONCLUSIVE. The test-harness wording "offline test suite
        # will FAIL" inside a missing-python3 suffix is a rare exception,
        # but that row is only present when python3 is MISSING — on a
        # healthy runner the string does not appear.
        # Check FAIL/PASS/etc. only in a preflight that was NOT triggered
        # by a missing-python3 state.
        if "python3:" in out and "✓" in out.split("python3:", 1)[-1].split("\n", 1)[0]:
            for banned in ("PASS", "FAIL", "INCONCLUSIVE", "EXECUTED", "READY"):
                self.assertNotIn(banned, out,
                                 f"preflight must not emit status word {banned!r}")
        # Present/missing glyphs are the only per-row status markers.
        self.assertTrue(("✓" in out) or ("✗" in out),
                        "preflight must emit at least one ✓ or ✗ glyph")


class CiPreflightMissingOptionalTest(unittest.TestCase):
    """Simulate missing OPTIONAL tools — exit must stay 0."""

    def test_empty_dir_prepended_still_exits_zero_when_forge_present(self) -> None:
        """Prepending an empty dir doesn't shadow real binaries.

        This is a sanity test: PATH=<empty_dir>:<real PATH> must still find
        forge (because real PATH comes after), so the preflight exits 0
        even though the empty dir doesn't provide anything.
        """
        if shutil.which("forge") is None:
            self.skipTest("forge not installed on this host — can't assert exit 0")
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty-bin"
            empty.mkdir()
            env = os.environ.copy()
            env["PATH"] = f"{empty}{os.pathsep}{env.get('PATH', '')}"
            proc = _run(env)
            self.assertEqual(
                proc.returncode, 0,
                f"preflight exited {proc.returncode}; "
                f"stdout={proc.stdout!r}; stderr={proc.stderr!r}",
            )
            self.assertIn("All critical tools present: YES",
                          proc.stdout + proc.stderr)

    def test_medusa_missing_is_reported_but_not_critical(self) -> None:
        """If medusa is absent, preflight should say so in 'Optional gaps'.

        We force the condition by running with a PATH that excludes the
        medusa directory (only relevant if medusa is actually installed).
        """
        if shutil.which("forge") is None:
            self.skipTest("forge not installed — preflight would exit 1 anyway")
        env = os.environ.copy()
        medusa = shutil.which("medusa")
        if medusa is not None:
            # Strip every dir that contains medusa (handles symlinks too).
            parts = [p for p in env.get("PATH", "").split(os.pathsep)
                     if not (p and (Path(p) / "medusa").exists())]
            env["PATH"] = os.pathsep.join(parts)
        proc = _run(env)
        self.assertEqual(proc.returncode, 0,
                         f"preflight failed with missing medusa: {proc.stderr}")
        combined = proc.stdout + proc.stderr
        self.assertIn("medusa:", combined)
        if shutil.which("medusa", path=env["PATH"]) is None:
            # Optional gaps line must mention medusa.
            gaps_line = combined.split("Optional gaps:", 1)
            self.assertEqual(len(gaps_line), 2,
                             "expected 'Optional gaps:' line in output")
            self.assertIn("medusa", gaps_line[1])


class CiPreflightMissingCriticalTest(unittest.TestCase):
    """Simulate missing CRITICAL tools — exit must be 1."""

    def test_missing_forge_fails_preflight(self) -> None:
        """Regression test called out by the PR 212 truth audit.

        If someone accidentally demotes forge to optional, the preflight
        would keep exiting 0 on a forge-less host and the workflow would
        silently hide a critical tool gap. This test catches that.
        """
        # Build a PATH that does not contain forge. On hosts without forge
        # installed to begin with, the current PATH already excludes it;
        # the removal loop below is a no-op.
        env = os.environ.copy()
        path_parts = env.get("PATH", "").split(os.pathsep)
        # Strip any directory that contains a forge binary (symlinks too).
        path_parts = [p for p in path_parts
                      if p and not (Path(p) / "forge").exists()]
        env["PATH"] = os.pathsep.join(path_parts) or _minimal_essential_path()

        # Sanity: the constructed env really has no forge on PATH.
        self.assertIsNone(shutil.which("forge", path=env["PATH"]),
                          "test setup failed to remove forge from PATH")

        proc = _run(env)
        self.assertEqual(proc.returncode, 1,
                         f"preflight should exit 1 when forge is missing; "
                         f"got {proc.returncode}. stdout={proc.stdout!r}")
        combined = proc.stdout + proc.stderr
        self.assertIn("All critical tools present: NO", combined)
        self.assertIn("Missing critical:", combined)
        missing_line = combined.split("Missing critical:", 1)[1]
        # "forge" must appear on the same line (before next newline).
        self.assertIn("forge", missing_line.split("\n", 1)[0])

    def test_reports_version_unknown_when_version_probe_fails(self) -> None:
        """A binary that fails its `--version` invocation still registers
        as present, with its VERSION reported as `version-unknown` rather
        than silently assumed to be a specific version. This is the
        'cannot-judge' behavior the truth audit requires.
        """
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = Path(tmp) / "bin"
            fake_bin.mkdir()
            # A broken `forge` that prints nothing and exits nonzero on
            # --version. Real `forge --version` prints on stdout.
            _write_executable(
                fake_bin / "forge",
                """
                #!/usr/bin/env bash
                exit 1
                """,
            )
            # Also need python3 to keep critical-set green.
            py = shutil.which("python3")
            self.assertIsNotNone(py, "python3 must exist for this test")
            essentials = _minimal_essential_path().split(os.pathsep)
            py_dir = str(Path(py).parent)
            if py_dir not in essentials:
                essentials.append(py_dir)
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join([str(fake_bin), *essentials])

            proc = _run(env)
            combined = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 0,
                             f"expected 0 with broken-but-present forge; "
                             f"got {proc.returncode}. out={combined!r}")
            m = re.search(r"forge:\s+✓\s+(\S+)", combined)
            self.assertIsNotNone(m, f"forge row not found in: {combined!r}")
            self.assertEqual(m.group(1), "version-unknown",
                             "broken --version must surface as 'version-unknown'")


class CiPreflightLibSourceTest(unittest.TestCase):
    """Verify the availability helper sources cleanly and exposes vars."""

    def test_helper_sets_has_vars(self) -> None:
        proc = subprocess.run(
            ["bash", "-c",
             f'. "{ROOT}/tools/lib/tool-availability.sh" && '
             'echo "HAS_FORGE=${HAS_FORGE:-unset}"; '
             'echo "HAS_PYTHON3=${HAS_PYTHON3:-unset}"; '
             'echo "HAS_MEDUSA=${HAS_MEDUSA:-unset}"; '
             'echo "HAS_TIMEOUT=${HAS_TIMEOUT:-unset}"'],
            capture_output=True, text=True, check=True,
        )
        for var in ("HAS_FORGE", "HAS_PYTHON3", "HAS_MEDUSA", "HAS_TIMEOUT"):
            self.assertIsNotNone(
                re.search(fr"^{var}=[01]$", proc.stdout, re.MULTILINE),
                f"{var} var missing or malformed in helper output:\n{proc.stdout}"
            )

    def test_helper_is_reentrant(self) -> None:
        """Double-sourcing must not re-probe or explode."""
        proc = subprocess.run(
            ["bash", "-c",
             f'. "{ROOT}/tools/lib/tool-availability.sh"; '
             f'. "{ROOT}/tools/lib/tool-availability.sh"; '
             'echo reentrant-ok'],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("reentrant-ok", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
