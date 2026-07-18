#!/usr/bin/env python3
"""Regression test for the audit-depth asymmetry-context-extract wiring (R81).

The `audit-depth` target runs the per-UNIT depth layer. Alongside the
`guard-context-extract.py` advisory sub-step (which emits
`guard_probe_packets.jsonl` before `depth-certificate-build`), an asymmetry
analog must run: `asymmetry-context-extract.py --workspace <ws>` filters the
sibling-path asymmetries emitted by `sibling-path-guard-diff` into a compact
`asymmetry_probe_packets.jsonl`, so the downstream probe never re-reads source.

Asserts:
* The Makefile `audit-depth` target text references `asymmetry-context-extract`.
* `make -n audit-depth WS=<ws>` expands to invoke `asymmetry-context-extract.py`.
* The asymmetry sub-step runs alongside (after) `guard-context-extract` and
  before the `depth-certificate-build` cert writer (the documented ordering).
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
MAKEFILE = REPO / "Makefile"


def _audit_depth_block(text: str) -> str:
    """Return the recipe text of the audit-depth target (up to the next target)."""
    lines = text.splitlines()
    out: list[str] = []
    in_block = False
    for line in lines:
        if re.match(r"^audit-depth:", line):
            in_block = True
            out.append(line)
            continue
        if in_block:
            # A new top-level target (non-indented, ends with ':') terminates the block.
            if re.match(r"^[A-Za-z0-9_.-]+:", line) and not line.startswith("\t"):
                break
            out.append(line)
    return "\n".join(out)


class TestAuditDepthAsymmetryWiring(unittest.TestCase):
    def setUp(self) -> None:
        self.text = MAKEFILE.read_text(encoding="utf-8")
        self.block = _audit_depth_block(self.text)
        self.assertTrue(self.block, "audit-depth target not found in Makefile")

    def test_makefile_references_asymmetry_context_extract(self) -> None:
        self.assertIn(
            "asymmetry-context-extract.py",
            self.block,
            "audit-depth target must reference tools/asymmetry-context-extract.py",
        )

    def test_asymmetry_runs_alongside_guard_context_extract(self) -> None:
        gce = self.block.find("guard-context-extract.py")
        ace = self.block.find("asymmetry-context-extract.py")
        dcb = self.block.find("depth-certificate-build.py")
        self.assertGreaterEqual(gce, 0, "guard-context-extract.py missing")
        self.assertGreaterEqual(ace, 0, "asymmetry-context-extract.py missing")
        self.assertGreaterEqual(dcb, 0, "depth-certificate-build.py missing")
        # asymmetry analog runs after guard-context-extract, before the cert writer.
        self.assertLess(gce, ace, "asymmetry-context-extract must run after guard-context-extract")
        self.assertLess(ace, dcb, "asymmetry-context-extract must run before depth-certificate-build")

    def test_asymmetry_is_rc_tolerant_advisory(self) -> None:
        # Mirror the gce_rc/sd_rc/dpi_rc pattern: an rc var + a WARN line.
        self.assertRegex(
            self.block,
            r"ace_rc=0;",
            "asymmetry sub-step must use an rc-tolerant ace_rc guard like the sibling steps",
        )
        self.assertIn(
            "asymmetry_probe_packets.jsonl",
            self.block,
            "asymmetry sub-step WARN line should name asymmetry_probe_packets.jsonl",
        )

    def test_make_n_expands_asymmetry_invocation(self) -> None:
        result = subprocess.run(
            ["make", "-n", "audit-depth", "WS=/Users/wolf/audits/hyperbridge"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"make -n audit-depth failed rc={result.returncode}\n{result.stderr}",
        )
        self.assertRegex(
            result.stdout,
            r"asymmetry-context-extract\.py --workspace",
            "make -n audit-depth must expand to an asymmetry-context-extract.py invocation",
        )


if __name__ == "__main__":
    unittest.main()
