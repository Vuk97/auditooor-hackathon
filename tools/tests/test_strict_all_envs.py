#!/usr/bin/env python3
"""Regression tests for the master strict switch (tools/lib/strict-all-envs.sh).

Operator 2026-07-04: "flip all advisory to strict, everywhere." The preamble,
sourced at every enforcement entrypoint, flips every AUDITOOOR_*_STRICT gate to
strict BY DEFAULT, while preserving two escape hatches:
  - AUDITOOOR_STRICT_ALL=0 restores advisory-first globally;
  - a per-gate ENV explicitly exported =0 is respected (only UNSET envs are set).
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
PREAMBLE = REPO / "tools" / "lib" / "strict-all-envs.sh"

SAMPLE_ENVS = [
    "AUDITOOOR_ESCALATION_WORKFLOW_STRICT",
    "AUDITOOOR_MANUAL_STEP_STRICT",
    "AUDITOOOR_ATTEST_SCHEMA_STRICT",
    "AUDITOOOR_ESCALATE_FIRST_STRICT",
    "AUDITOOOR_CLAIM_CITATION_STRICT",
]


def _run(script: str, extra_env: dict | None = None) -> str:
    env = {"PATH": "/usr/bin:/bin"}
    if extra_env:
        env.update(extra_env)
    r = subprocess.run(["bash", "-c", f". {PREAMBLE}; {script}"],
                       capture_output=True, text=True, env=env)
    return r.stdout.strip()

class StrictAllEnvsTest(unittest.TestCase):
    def test_preamble_exists_and_covers_many_envs(self):
        self.assertTrue(PREAMBLE.is_file(), "strict-all-envs.sh missing")
        txt = PREAMBLE.read_text()
        n = len(re.findall(r"export AUDITOOOR_\w*STRICT\w*=", txt))
        self.assertGreaterEqual(n, 50, f"expected many strict envs, got {n}")
        # gated on the master switch
        self.assertIn("AUDITOOOR_STRICT_ALL", txt)

    def test_default_on_flips_envs(self):
        for e in SAMPLE_ENVS:
            out = _run(f'echo "${e}"')
            self.assertEqual(out, "1", f"{e} should default to 1 (strict) when STRICT_ALL unset")

    def test_strict_all_zero_opts_out(self):
        for e in SAMPLE_ENVS:
            out = _run(f'echo "[${{{e}:-UNSET}}]"', extra_env={"AUDITOOOR_STRICT_ALL": "0"})
            self.assertEqual(out, "[UNSET]", f"{e} should be UNSET when STRICT_ALL=0")

    def test_per_gate_zero_override_respected(self):
        e = "AUDITOOOR_ESCALATION_WORKFLOW_STRICT"
        out = _run(f'echo "${e}"', extra_env={e: "0"})
        self.assertEqual(out, "0", "an explicit per-gate =0 must be respected (not overridden to 1)")


if __name__ == "__main__":
    unittest.main()
