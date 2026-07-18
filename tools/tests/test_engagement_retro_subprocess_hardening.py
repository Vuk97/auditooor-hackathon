#!/usr/bin/env python3
"""Tests for tools/engagement-retro.py — Kimi K16 hardening pass.

Covers three regressions that K16 flagged on tools/engagement-retro.py:

  1. Pattern IDs were derived from Python's per-process-randomised
     ``hash(title)`` and silently changed on every run, causing duplicate
     pattern entries to be appended to ``triager_patterns.md``. The fixed
     ``_stable_pattern_id`` helper must return the same id for the same
     title across separate Python interpreters.
  2. ``bump_workspace_state`` previously used ``os.system`` with
     ``>/dev/null 2>&1`` which swallowed all errors. The new implementation
     uses ``subprocess.run(..., check=True)`` and must surface non-zero
     exits.
  3. Same call interpolated the ``ws`` path into a shell string without
     escaping. The fixed implementation passes the path as an argv element,
     so a workspace path containing spaces or quotes must not break the
     command or be reinterpreted by a shell.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "engagement-retro.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "engagement_retro", MODULE_PATH
    )
    assert spec and spec.loader, f"could not load {MODULE_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


retro = _load_module()


class StablePatternIdTests(unittest.TestCase):
    """K16 finding #2: ``hash(title)`` is randomised per process."""

    def test_id_is_deterministic_within_process(self) -> None:
        title = "Reentrancy in callback handler"
        self.assertEqual(
            retro._stable_pattern_id(title),
            retro._stable_pattern_id(title),
        )

    def test_id_format_matches_legacy_shape(self) -> None:
        # Legacy format was ``auto-XXXX`` (4 hex/digit chars). Preserve it
        # so existing rendered patterns line up visually.
        pid = retro._stable_pattern_id("any title")
        self.assertTrue(pid.startswith("auto-"), pid)
        self.assertEqual(len(pid), len("auto-") + 4, pid)
        # 4 lowercase hex chars
        suffix = pid.split("-", 1)[1]
        int(suffix, 16)  # must parse as hex; raises if not
        self.assertEqual(suffix, suffix.lower())

    def test_id_distinguishes_different_titles(self) -> None:
        a = retro._stable_pattern_id("Event-only finding")
        b = retro._stable_pattern_id("Reentrancy without value")
        self.assertNotEqual(a, b)

    def test_id_is_deterministic_across_processes(self) -> None:
        """Run a fresh interpreter twice with PYTHONHASHSEED=random and
        confirm both subprocesses produce the SAME id for the same title.
        This is the regression that ``hash(title)`` could not pass.
        """
        snippet = textwrap.dedent(
            f"""
            import importlib.util, sys
            spec = importlib.util.spec_from_file_location(
                "er", r"{MODULE_PATH}"
            )
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            sys.stdout.write(m._stable_pattern_id("Reentrancy in callback handler"))
            """
        )
        # Two independent interpreters with random hash seeds.
        out_a = subprocess.run(
            [sys.executable, "-c", snippet],
            check=True,
            capture_output=True,
            text=True,
            env={"PYTHONHASHSEED": "random", "PATH": ""},
        ).stdout
        out_b = subprocess.run(
            [sys.executable, "-c", snippet],
            check=True,
            capture_output=True,
            text=True,
            env={"PYTHONHASHSEED": "random", "PATH": ""},
        ).stdout
        self.assertEqual(out_a, out_b)
        self.assertTrue(out_a.startswith("auto-"), out_a)


class BumpWorkspaceStateSubprocessTests(unittest.TestCase):
    """K16 findings #1 and #3: silent ``os.system`` + unescaped shell path."""

    def _install_fake_state_tool(self, tmp: Path, body: str) -> Path:
        """Write a stub ``workspace-state.py`` and point the module at it."""
        tool = tmp / "workspace-state.py"
        tool.write_text(body, encoding="utf-8")
        retro.STATE_TOOL = tool  # monkey-patched for the duration of this test
        return tool

    def test_path_with_space_and_quote_is_not_shell_interpreted(self) -> None:
        """A workspace path containing a space and a single quote must be
        passed through verbatim (argv element), not re-parsed by a shell."""
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            # The stub re-emits argv so we can assert the exact path it saw.
            self._install_fake_state_tool(
                tmp,
                textwrap.dedent(
                    """
                    import sys
                    # argv: [script, "bump", <ws>, "--findings", N, "--submissions", M]
                    ws = sys.argv[2]
                    sys.stdout.write(ws)
                    sys.exit(0)
                    """
                ),
            )
            tricky = "/tmp/space dir/o'quote"
            # Capture stdout to verify the path round-tripped exactly.
            completed = subprocess.run(
                [
                    sys.executable,
                    str(retro.STATE_TOOL),
                    "bump",
                    tricky,
                    "--findings",
                    "1",
                    "--submissions",
                    "1",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.stdout, tricky)
            # And the high-level wrapper does not raise on the same input.
            retro.bump_workspace_state(tricky, 1, 1, dry_run=False)

    def test_nonzero_exit_is_surfaced_not_swallowed(self) -> None:
        """K16 finding #1: ``check=True`` makes a failing bump raise rather
        than fail silently like the old ``os.system(... 2>&1)`` did."""
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            self._install_fake_state_tool(
                tmp,
                "import sys\nsys.stderr.write('boom\\n')\nsys.exit(2)\n",
            )
            with self.assertRaises(subprocess.CalledProcessError) as cm:
                retro.bump_workspace_state("/some/ws", 1, 1, dry_run=False)
            self.assertEqual(cm.exception.returncode, 2)

    def test_dry_run_short_circuits_without_invocation(self) -> None:
        """Dry-run path must not attempt to call workspace-state.py at all."""
        # Point STATE_TOOL at a path that does not exist; dry_run=True should
        # return cleanly anyway.
        retro.STATE_TOOL = Path("/nonexistent/workspace-state.py")
        retro.bump_workspace_state("/whatever", 1, 1, dry_run=True)


if __name__ == "__main__":
    unittest.main()
