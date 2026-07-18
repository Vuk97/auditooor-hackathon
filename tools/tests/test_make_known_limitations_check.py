#!/usr/bin/env python3
"""Regression tests for `make known-limitations-check`.

Contract: a single-entry burn-down gate that runs the detector-lint flag
matrix + focused unit tests, prints one PASS/WARN/FAIL line per check, and
exits with rc 0 (default mode, advisory WARN allowed) or 1 (any FAIL, or
STRICT=1 promoted WARN).

Tests:

  1. test_default_mode_runs_and_exits_zero_with_expected_lines
     Default invocation prints the expected per-gate lines and exits 0
     (current main has at least one advisory WARN row from
     `--fail-unknown-function-kind`, but no hard FAIL).

  2. test_default_mode_emits_passwarnfail_summary
     The Summary block lists every gate executed.

  3. test_strict_mode_promotes_warn_to_fail
     `STRICT=1` flips the rc to non-zero whenever any flag exits non-zero
     (it also adds the audit-closeout regression to the unittest set).

  4. test_strict_mode_adds_audit_closeout_regression
     STRICT=1 runs `tools.tests.test_audit_closeout_check`.

  5. test_single_failing_gate_flips_overall_rc_in_strict
     With a synthetic detector-lint stub that always exits non-zero, the
     overall rc is non-zero in STRICT mode (proves the rc plumbing).

  6. test_single_failing_unittest_flips_overall_rc
     With a synthetic unittest target that fails, the overall rc is
     non-zero even in default mode.

The first four tests run against the real repo (read-only). Tests 5 and 6
copy the script into a temp dir and stub `python3 tools/detector-lint.py`
+ `python3 -m unittest` via a shim PATH entry so the harness is exercised
without mutating the real lint or test corpus.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "known-limitations-check.sh"


def _run_make(target: str, *, strict: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("MAKEFLAGS", None)  # avoid -j parallel from outer make
    if strict is not None:
        env["STRICT"] = strict
    return subprocess.run(
        ["make", target],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


class TestMakeKnownLimitationsCheckLive(unittest.TestCase):
    """Live invocation tests against the real repo. Read-only."""

    def test_default_mode_runs_and_exits_zero_with_expected_lines(self) -> None:
        proc = _run_make("known-limitations-check")
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"expected rc=0 in default mode, got {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        # Header line.
        self.assertIn("known-limitations-check", proc.stdout)
        self.assertIn("STRICT=0", proc.stdout)
        # Each detector-lint gate must surface (PASS / WARN / FAIL on its
        # own line — we only assert the label substring is present).
        for label in (
            "detector-lint (default;",
            "detector-lint --fail-unknown-function-kind",
            "detector-lint --fail-high-tier-regex-only",
            "detector-lint --fail-high-tier-placeholder-fp-guards",
            "function-kind + placeholder-FP-guard lint tests",
            "known-limitations burn-down accounting tests",
        ):
            self.assertIn(label, proc.stdout, msg=f"missing gate label: {label}")

    def test_default_mode_emits_passwarnfail_summary(self) -> None:
        proc = _run_make("known-limitations-check")
        self.assertIn("Summary", proc.stdout)
        # Final outcome line.
        self.assertRegex(
            proc.stdout,
            r"known-limitations-check: (PASS|FAIL)",
        )
        self.assertRegex(proc.stdout, r"total: \d+")

    def test_strict_mode_adds_audit_closeout_regression(self) -> None:
        proc = _run_make("known-limitations-check", strict="1")
        # STRICT=1 always runs the audit-closeout regression line.
        self.assertIn("audit-closeout regression (STRICT)", proc.stdout)
        self.assertIn("STRICT=1", proc.stdout)


class TestMakeKnownLimitationsCheckShimRC(unittest.TestCase):
    """Hermetic rc-plumbing tests: stub detector-lint + unittest via PATH."""

    def _make_shim_repo(
        self,
        *,
        lint_rc: int = 0,
        unittest_rc: int = 0,
    ) -> tempfile.TemporaryDirectory:
        """Build a tiny repo that has the script + minimal layout, plus a
        `python3` shim that returns the requested rc for the lint and
        unittest invocations.

        Returns the `TemporaryDirectory` object itself so callers can use
        `with self._make_shim_repo(...) as tmp_path:` and get the path
        string per `tempfile.TemporaryDirectory.__enter__`.
        """
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        (root / "tools").mkdir()
        # Copy the real script.
        (root / "tools" / "known-limitations-check.sh").write_text(
            SCRIPT.read_text()
        )
        os.chmod(root / "tools" / "known-limitations-check.sh", 0o755)
        # Drop a stub detector-lint.py — the shim picks the rc, but the
        # path needs to exist so the script doesn't print "no such file".
        (root / "tools" / "detector-lint.py").write_text("# stub\n")

        # `python3` shim. The script invokes:
        #   python3 tools/detector-lint.py [...]
        #   python3 -m unittest tools.tests.* [...]
        # We dispatch on the first argv slot.
        bin_dir = root / "_shim_bin"
        bin_dir.mkdir()
        shim = bin_dir / "python3"
        shim.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                # Hermetic python3 shim used by
                # tools/tests/test_make_known_limitations_check.py.
                # Dispatch on the first arg.
                first="$1"
                case "$first" in
                  tools/detector-lint.py) exit {lint_rc} ;;
                  -m)
                    # `python3 -m unittest ...`
                    exit {unittest_rc}
                    ;;
                  *) exit 0 ;;
                esac
                """
            )
        )
        os.chmod(shim, 0o755)
        return tmp

    def _run_shim(
        self,
        tmp_path: str,
        *,
        strict: str = "0",
    ) -> subprocess.CompletedProcess:
        root = Path(tmp_path)
        env = dict(os.environ)
        env["PATH"] = f"{root / '_shim_bin'}:{env.get('PATH', '')}"
        env["STRICT"] = strict
        return subprocess.run(
            ["bash", str(root / "tools" / "known-limitations-check.sh")],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )

    def test_all_pass_default_rc_zero(self) -> None:
        with self._make_shim_repo(lint_rc=0, unittest_rc=0) as tmp:
            proc = self._run_shim(tmp, strict="0")
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"expected rc=0 when all gates PASS, got {proc.returncode}\n"
            f"stdout:\n{proc.stdout}",
        )
        self.assertIn("known-limitations-check: PASS", proc.stdout)

    def test_lint_failing_in_default_warns_but_passes(self) -> None:
        with self._make_shim_repo(lint_rc=1, unittest_rc=0) as tmp:
            proc = self._run_shim(tmp, strict="0")
        # Default lint pass is FAIL-level (it always fails on HIGH-tier
        # mismatches). The shim makes EVERY lint call rc=1, so the
        # default-pass row will be FAIL.
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("[FAIL] detector-lint (default", proc.stdout)
        self.assertIn("[WARN] detector-lint --fail-unknown-function-kind", proc.stdout)

    def test_lint_failing_in_strict_flips_rc(self) -> None:
        with self._make_shim_repo(lint_rc=1, unittest_rc=0) as tmp:
            proc = self._run_shim(tmp, strict="1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("known-limitations-check: FAIL", proc.stdout)
        self.assertIn("[FAIL] detector-lint --fail-unknown-function-kind", proc.stdout)

    def test_unittest_failing_flips_rc_default(self) -> None:
        # Lint passes everywhere (rc=0); only the unittest set fails.
        with self._make_shim_repo(lint_rc=0, unittest_rc=1) as tmp:
            proc = self._run_shim(tmp, strict="0")
        self.assertNotEqual(
            proc.returncode,
            0,
            msg=f"expected rc!=0 when unittests FAIL, got {proc.returncode}\n"
            f"stdout:\n{proc.stdout}",
        )
        self.assertIn(
            "[FAIL] function-kind + placeholder-FP-guard lint tests",
            proc.stdout,
        )

    def test_strict_mode_lists_audit_closeout_in_summary(self) -> None:
        with self._make_shim_repo(lint_rc=0, unittest_rc=0) as tmp:
            proc = self._run_shim(tmp, strict="1")
        self.assertEqual(proc.returncode, 0, msg=proc.stdout)
        self.assertIn("audit-closeout regression (STRICT)", proc.stdout)


if __name__ == "__main__":
    unittest.main()
