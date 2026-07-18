#!/usr/bin/env python3
"""Kimi K8 review item #2 — subprocess timeout regression lock for
``tools/swarm-orchestrator.py``.

Background:
  Kimi K8 flagged that both ``subprocess.run`` call sites in
  swarm-orchestrator (``run_ccia`` and ``_real_dispatch_via_llm``) lacked a
  ``timeout=`` argument, so a hung child could wedge the entire
  orchestrator. This test exercises the now-bounded code path on
  ``run_ccia`` and confirms:

    1. A real child that genuinely outlasts the timeout raises
       ``subprocess.TimeoutExpired`` internally.
    2. The handler logs a ``[swarm] CCIA timed out`` line to stderr.
    3. The function returns ``{}`` (the existing "no data" sentinel) rather
       than crashing or deadlocking.

The test stubs the resolved CCIA script to ``sh -c "sleep 999"`` and shrinks
``CCIA_TIMEOUT_SEC`` to a fraction of a second so the test stays under one
second of wall time. Hermetic — no network, no real CCIA, no real LLM.
"""
from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "swarm-orchestrator.py"


def _load_swarm_module():
    """Import swarm-orchestrator.py as a module despite the hyphen in its name.

    Sibling helpers in ``tools/`` (e.g. ``mining_brief_context``) must be on
    ``sys.path`` before ``exec_module`` runs.
    """
    tools_dir = str(ROOT / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("swarm_orchestrator", TOOL)
    assert spec and spec.loader, "swarm-orchestrator.py missing"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SWARM = _load_swarm_module()


class RunCciaTimeoutSurfacesStructuredFailureTest(unittest.TestCase):
    """Locks the K8 #2 fix: a hung CCIA child must NOT wedge the orchestrator."""

    def test_run_ccia_timeout_returns_empty_dict_and_logs_to_stderr(self) -> None:
        # Replace the resolved ccia.py with a shell stub that sleeps far longer
        # than our test timeout. We patch subprocess.run's argv via a wrapper
        # so the function under test still flows through its real codepath.
        real_run = SWARM.subprocess.run

        def _hung_ccia(cmd, **kwargs):
            # Discard the original argv (it points at the real ccia.py) and
            # substitute a deliberate hang. The timeout kwarg is preserved so
            # the real subprocess.run raises TimeoutExpired exactly as it
            # would in production.
            return real_run(["sh", "-c", "sleep 999"], **kwargs)

        buf = io.StringIO()
        # Shrink the timeout so the test takes <1s rather than 600s.
        with patch.object(SWARM, "CCIA_TIMEOUT_SEC", 0.2), \
             patch.object(SWARM.subprocess, "run", side_effect=_hung_ccia), \
             redirect_stderr(buf):
            result = SWARM.run_ccia(Path("/tmp/does-not-matter"), src="src")

        # Structured failure: the existing "no data" sentinel, NOT a raise.
        self.assertEqual(result, {})

        # Handler must have logged a recognisable timeout line (Kimi K8 #2).
        stderr_text = buf.getvalue()
        self.assertIn("[swarm] CCIA timed out", stderr_text)
        self.assertIn("0.2", stderr_text)  # the timeout value we patched in

    def test_run_ccia_timeout_constant_is_finite_and_positive(self) -> None:
        """Static guard: the module-level budget MUST be a finite positive number.

        A zero/negative/None value would silently disable the K8 fix and
        re-introduce the deadlock. This is the kind of regression a future
        refactor could introduce without anyone noticing.
        """
        self.assertIsInstance(SWARM.CCIA_TIMEOUT_SEC, (int, float))
        self.assertGreater(SWARM.CCIA_TIMEOUT_SEC, 0)
        self.assertIsInstance(SWARM.LLM_DISPATCH_TIMEOUT_SEC, (int, float))
        self.assertGreater(SWARM.LLM_DISPATCH_TIMEOUT_SEC, 0)


if __name__ == "__main__":
    unittest.main()
