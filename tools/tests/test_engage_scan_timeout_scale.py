"""Guard test - engage._solidity_scan_timeout scales the scan stage budget
by in-scope .sol count so large Solidity workspaces (e.g. beanstalk, mezo)
do not abort the scan stage with rc=124.

Root cause this guards (BEAN audit-deep, 2026-06-12): the flat
SCAN_TIMEOUT=1200 (20m) was SHORTER than workspace-scan-orchestrator.py's own
1800s internal budget, so the shell `timeout` wrapper killed the orchestrator
(rc=124) before it could finish on a 184-contract workspace, aborting
audit-deep before any engine ran.

Contract:
  - small/empty workspace (<=40 .sol) keeps the 1200s floor (backward-compat);
  - large workspace scales above the 1800s orchestrator internal budget and is
    clamped to [1900, 3600];
  - AUDITOOOR_SCAN_TIMEOUT env override wins unconditionally.
"""
from __future__ import annotations

import importlib.util
import os
import tempfile
import types
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ENGAGE = REPO / "tools" / "engage.py"


def _load_engage_module() -> types.ModuleType:
    # engage.py uses top-level `from submission_paths import ...` so the
    # tools/ directory must be on sys.path when we exec it here.
    import sys
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage", ENGAGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_ws(n_sol: int, *, skipped: int = 0) -> Path:
    ws = Path(tempfile.mkdtemp())
    for i in range(n_sol):
        (ws / f"C{i}.sol").write_text("// SPDX\ncontract C {}\n")
    # files under a skip dir must NOT count toward the in-scope total
    if skipped:
        nm = ws / "node_modules"
        nm.mkdir()
        for i in range(skipped):
            (nm / f"Dep{i}.sol").write_text("contract D {}\n")
    return ws


class ScanTimeoutScaleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.m = _load_engage_module()
        # ensure a clean env for the override assertions
        self._saved = os.environ.pop("AUDITOOOR_SCAN_TIMEOUT", None)

    def tearDown(self) -> None:
        os.environ.pop("AUDITOOOR_SCAN_TIMEOUT", None)
        if self._saved is not None:
            os.environ["AUDITOOOR_SCAN_TIMEOUT"] = self._saved

    def test_small_workspace_keeps_floor(self) -> None:
        # <=40 .sol stays at the historical 1200s floor (backward-compat).
        ws = _make_ws(5)
        self.assertEqual(self.m._solidity_scan_timeout(ws), self.m.SCAN_TIMEOUT)
        self.assertEqual(self.m.SCAN_TIMEOUT, 1200)

    def test_empty_workspace_keeps_floor(self) -> None:
        ws = Path(tempfile.mkdtemp())
        self.assertEqual(self.m._solidity_scan_timeout(ws), 1200)

    def test_large_workspace_exceeds_orchestrator_internal_budget(self) -> None:
        # The bug: the budget must exceed the orchestrator's own 1800s internal
        # timeout so the shell wrapper does not kill it first (rc=124).
        ws = _make_ws(184)
        to = self.m._solidity_scan_timeout(ws)
        self.assertGreater(to, 1800, "must exceed orchestrator's 1800s internal budget")
        self.assertLessEqual(to, 3600, "clamped at 3600s ceiling")
        self.assertGreaterEqual(to, 1900, "clamped at 1900s floor for >40 .sol")

    def test_scales_monotonically_then_clamps(self) -> None:
        small = self.m._solidity_scan_timeout(_make_ws(50))
        big = self.m._solidity_scan_timeout(_make_ws(120))
        self.assertGreaterEqual(big, small)
        self.assertLessEqual(big, 3600)
        # well past the ceiling input still clamps
        self.assertEqual(self.m._solidity_scan_timeout(_make_ws(400)), 3600)

    def test_skip_dirs_do_not_inflate_count(self) -> None:
        # node_modules/lib/out .sol must not push a small in-scope tree over the
        # floor threshold.
        ws = _make_ws(3, skipped=200)
        self.assertEqual(self.m._solidity_scan_timeout(ws), 1200)

    def test_env_override_wins(self) -> None:
        os.environ["AUDITOOOR_SCAN_TIMEOUT"] = "999"
        ws = _make_ws(184)  # would otherwise be 3600
        self.assertEqual(self.m._solidity_scan_timeout(ws), 999)


if __name__ == "__main__":
    unittest.main()
