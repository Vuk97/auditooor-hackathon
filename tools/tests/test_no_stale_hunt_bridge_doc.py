#!/usr/bin/env python3
"""Guard: no tracked doc/json/runbook references the non-existent stale bridge target,
and the canonical step-3 runbook entry documents the real invocation.

There is NO hunt-sidecar-bridge Makefile target - the bridge is invoked directly as
`python3 tools/hunt-sidecar-bridge.py --workspace <ws>`. A stale "<make> hunt-sidecar-bridge"
string in any doc/runbook/hook misleads an orchestrator into running a target that does not
exist (silently skipping the bridge -> coverage-gate -> residual-only step). This test
fails closed if that literal reappears anywhere in the tracked tree, and asserts step-3 of
the canonical runbook names the python bridge, the coverage gate, and the residual concept.

Note: STALE_LITERAL is assembled at runtime from tokens so this very test file does not
itself contain the contiguous forbidden string (which would self-trip the git-grep scan).

Stdlib-only (subprocess + json + pathlib). Run from anywhere inside the repo.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

# The exact non-existent target string that must never appear in a tracked file.
# Assembled from tokens so this test file does not itself contain the contiguous literal.
STALE_LITERAL = "make" + " " + "hunt-sidecar-bridge"


def _repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=str(Path(__file__).resolve().parent),
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(out.stdout.strip())


class TestNoStaleHuntBridgeDoc(unittest.TestCase):
    def setUp(self):
        self.root = _repo_root()

    def test_no_stale_make_hunt_sidecar_bridge_literal(self):
        """No tracked file may contain the stale non-existent make-target literal."""
        proc = subprocess.run(
            ["git", "grep", "-n", "-F", STALE_LITERAL],
            cwd=str(self.root),
            capture_output=True,
            text=True,
        )
        # git grep exits 1 (no matches) = clean; 0 = matches found = fail; >1 = error.
        if proc.returncode == 1:
            return  # clean
        self.assertNotEqual(
            proc.returncode,
            0,
            msg=(
                "Stale non-existent make target (" + STALE_LITERAL + ") found in tracked "
                "files - use `python3 tools/hunt-sidecar-bridge.py --workspace <ws>`:\n"
                + proc.stdout
            ),
        )
        # returncode >1 means git grep errored (e.g. not a repo) - surface it.
        self.fail("git grep errored:\n" + (proc.stderr or proc.stdout))

    def test_step3_runbook_documents_canonical_bridge_gate_residual(self):
        """readme_runbook_steps.json step-3 must name the python bridge, coverage gate,
        and the residual-only concept."""
        manifest_path = self.root / "tools" / "readme_runbook_steps.json"
        self.assertTrue(manifest_path.is_file(), f"missing {manifest_path}")
        manifest = json.loads(manifest_path.read_text())
        steps = manifest.get("steps", [])
        step3 = next((s for s in steps if s.get("step_id") == "step-3"), None)
        self.assertIsNotNone(step3, "step-3 not found in runbook manifest")
        wmb = step3.get("what_must_be_done", "")
        self.assertIn(
            "hunt-sidecar-bridge.py",
            wmb,
            "step-3 must reference the python bridge tool hunt-sidecar-bridge.py",
        )
        self.assertIn(
            "hunt-coverage-gate.py",
            wmb,
            "step-3 must reference the coverage gate hunt-coverage-gate.py",
        )
        self.assertIn(
            "residual",
            wmb.lower(),
            "step-3 must instruct hunting ONLY the residual (never a full re-hunt)",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
