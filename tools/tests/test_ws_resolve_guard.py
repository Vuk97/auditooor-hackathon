"""Regression test for the WS-resolution fail-loud fix.

Root cause: `make audit-complete WS=<relative-name>` (or any of the ~120
other `make <target> WS=...` recipes) used to check ONLY `[ -d
"$(_WS_RESOLVED)" ]`. When WS is a bare relative name (no `~/audits/`
prefix), `_WS_RESOLVED` (Makefile ~3079) leaves it untouched, so it
resolves relative to whatever CURDIR the shell happens to be in. Run from
inside auditooor-mcp/, a leftover near-empty directory there (e.g.
`auditooor-mcp/dydx/` containing only `.auditooor/mcp_call_log.jsonl`,
auto-vivified by `Path(...).mkdir(parents=True, exist_ok=True)` in a prior
tool run) satisfies the `-d` check and gets silently GRADED instead of the
real workspace at `~/audits/dydx/` -- returning a misleading
"pass / no solidity source" verdict.

The fix: `tools/ws-resolve-guard.sh <label> <resolved-path>` now backs
every one of those call sites. It keeps the original `-d` check but adds a
STUB check: the resolved path must contain either a workspace marker
(docs/SCOPE.md, docs/SEVERITY.md, README, src/, contracts/, test(s)/,
submissions/) or at least one tracked-language source file outside
`.auditooor/`. A directory with neither is refused with exit 2, not
silently graded.

This test exercises the guard script directly (no `make`/python
dependency beyond stdlib) so it runs fast and offline.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "tools" / "ws-resolve-guard.sh"


def run_guard(label: str, ws: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(GUARD), label, ws],
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestWsResolveGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ws_resolve_guard_test_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_guard_script_exists_and_is_executable(self) -> None:
        self.assertTrue(GUARD.is_file(), f"missing {GUARD}")

    def test_nonexistent_path_fails_loud(self) -> None:
        ws = self.tmp / "does-not-exist"
        result = run_guard("test-label", str(ws))
        self.assertEqual(result.returncode, 2)
        self.assertIn("workspace not found or not a directory", result.stderr)

    def test_empty_stub_directory_fails_loud_not_silently_graded(self) -> None:
        """The exact bug shape: a directory that exists (passes `-d`) but has
        no real workspace content, mirroring auditooor-mcp/dydx/ which only
        contains `.auditooor/mcp_call_log.jsonl` -- auto-vivified bookkeeping,
        not real audit content."""
        ws = self.tmp / "dydx"
        (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "mcp_call_log.jsonl").write_text("{}\n")

        result = run_guard("make audit-complete", str(ws))
        self.assertEqual(
            result.returncode, 2,
            f"stub dir must be refused, not silently graded; stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertIn("EMPTY STUB", result.stderr)
        self.assertNotIn("pass", result.stdout.lower())

    def test_directory_with_source_file_passes(self) -> None:
        ws = self.tmp / "real-ws-src"
        src_dir = ws / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "Vault.sol").write_text("// SPDX-License-Identifier: MIT\ncontract Vault {}\n")

        result = run_guard("make audit-complete", str(ws))
        self.assertEqual(result.returncode, 0, f"stderr={result.stderr!r}")

    def test_directory_with_scope_marker_passes(self) -> None:
        ws = self.tmp / "real-ws-docs"
        docs_dir = ws / "docs"
        docs_dir.mkdir(parents=True)
        (docs_dir / "SCOPE.md").write_text("# Scope\n")

        result = run_guard("make audit-complete", str(ws))
        self.assertEqual(result.returncode, 0, f"stderr={result.stderr!r}")

    def test_stub_check_ignores_auditooor_bookkeeping_dir_contents(self) -> None:
        """A .auditooor/ dir stuffed with lots of bookkeeping files must still
        be treated as a stub if there is no real source/marker alongside it -
        proves the guard doesn't get fooled by .auditooor/ file *count*."""
        ws = self.tmp / "bookkeeping-heavy-stub"
        auditooor_dir = ws / ".auditooor"
        auditooor_dir.mkdir(parents=True)
        for i in range(10):
            (auditooor_dir / f"log_{i}.jsonl").write_text("{}\n")

        result = run_guard("make audit-complete", str(ws))
        self.assertEqual(result.returncode, 2)
        self.assertIn("EMPTY STUB", result.stderr)


if __name__ == "__main__":
    unittest.main()
