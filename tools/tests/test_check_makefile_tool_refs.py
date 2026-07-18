#!/usr/bin/env python3
"""Regression tests for ``tools/check-makefile-tool-refs.py``.

After PRs #163 and #171 fixed Makefile ``WS=~user/`` and bare ``WS=~``
handling, this checker had no test confirming it stays robust when the
caller's environment contains tilde-bearing values. The checker reads
``Makefile`` directly, but it is invoked from CI flows that frequently
ship tilde-bearing ``WS`` env vars — so we want belt-and-suspenders
guarantees that no ``AttributeError`` (e.g. ``NoneType.expanduser``)
slips in when those vars are present in the environment.

Coverage:

  1. Plain invocation under the real repo Makefile — must exit 0 and
     print ``[tool-refs] OK``.
  2. ``WS=~`` (bare tilde) — must not affect the checker (no env read)
     and exit 0.
  3. ``WS=~root`` (``getpwnam``-style tilde with username) — must not
     affect the checker and exit 0.
  4. ``WS=/abs/path`` (already-absolute) — must not affect the checker
     and exit 0.
  5. Negative path: a synthetic Makefile that references a missing tool
     causes the checker to exit 1 — proves the checker still
     differentiates good vs. bad inputs.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
CHECKER = REPO / "tools" / "check-makefile-tool-refs.py"


def _run(env_overrides: dict[str, str] | None = None,
         repo: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Invoke the checker with optional env overrides.

    The checker resolves the Makefile via ``Path(__file__).parent.parent``
    so passing ``repo`` lets us point it at a synthetic repo (used by the
    negative-path test).
    """
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    target = (repo / "tools" / "check-makefile-tool-refs.py") if repo else CHECKER
    return subprocess.run(
        [sys.executable, str(target)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


class CheckMakefileToolRefsTest(unittest.TestCase):
    """Tilde-env tripwire + happy/sad path smoke for the tool-refs checker."""

    def test_checker_exists(self) -> None:
        self.assertTrue(CHECKER.is_file(), f"checker missing at {CHECKER}")

    def test_plain_invocation_exits_zero(self) -> None:
        proc = _run()
        self.assertEqual(
            proc.returncode, 0,
            f"plain invocation failed:\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
        self.assertIn("[tool-refs] OK", proc.stdout)

    def test_tilde_bare_ws_no_attribute_error(self) -> None:
        proc = _run({"WS": "~"})
        self.assertEqual(
            proc.returncode, 0,
            f"WS=~ broke checker:\nstderr={proc.stderr}",
        )
        self.assertNotIn("AttributeError", proc.stderr)
        self.assertIn("[tool-refs] OK", proc.stdout)

    def test_tilde_user_ws_no_attribute_error(self) -> None:
        proc = _run({"WS": "~root"})
        self.assertEqual(
            proc.returncode, 0,
            f"WS=~root broke checker:\nstderr={proc.stderr}",
        )
        self.assertNotIn("AttributeError", proc.stderr)
        self.assertIn("[tool-refs] OK", proc.stdout)

    def test_absolute_ws_path_unaffected(self) -> None:
        proc = _run({"WS": "/abs/path/that/does/not/exist"})
        self.assertEqual(
            proc.returncode, 0,
            f"WS=/abs/... broke checker:\nstderr={proc.stderr}",
        )
        self.assertNotIn("AttributeError", proc.stderr)
        self.assertIn("[tool-refs] OK", proc.stdout)

    def test_synthetic_missing_tool_fails(self) -> None:
        """Sanity: when the Makefile actually does reference a missing tool,
        the checker exits 1. Confirms the checker is not unconditionally
        passing under our env perturbations."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            (tmp / "tools").mkdir()
            # Copy the checker into the synthetic repo so its
            # ``Path(__file__).parent.parent`` lands on tmp.
            checker_copy = tmp / "tools" / "check-makefile-tool-refs.py"
            checker_copy.write_bytes(CHECKER.read_bytes())
            checker_copy.chmod(0o755)
            (tmp / "Makefile").write_text(textwrap.dedent("""\
                fake-target:
                \tpython3 tools/this-tool-does-not-exist.py
            """))
            proc = _run(repo=tmp)
        self.assertEqual(
            proc.returncode, 1,
            f"synthetic missing tool was not flagged:\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
        self.assertIn("Missing Makefile tool references", proc.stdout)
        self.assertIn("tools/this-tool-does-not-exist.py", proc.stdout)


if __name__ == "__main__":
    unittest.main()
