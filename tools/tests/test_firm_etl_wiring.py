#!/usr/bin/env python3
"""Wave-2 W2.4 execution-wiring regression guard.

The 7 audit-firm PDF deep-mine ETL parsers
(``tools/hackerman-etl-from-audit-firm-pdf-<firm>.py`` for zellic, tob,
chainsecurity, cyfrin, openzeppelin, sherlock, spearbit) were shipped and
unit-tested but for a long time had NO Makefile producer target, so the
corpus sat at 0 records (registry ``makefile_target: null``).

``wave2-b-close-readiness`` already checks parser *presence* (>= 7 firm
scripts on disk). This test upgrades that presence-only signal into an
*execution-wiring* assertion: every discovered firm parser must

  (b) have a real, non-``.PHONY`` recipe target
      ``hackerman-etl-from-audit-firm-pdf-<firm>:`` in the Makefile, and
  (c) be present as a key in source-miner-backlog ``COMMANDS``.

So a future firm parser added without wiring it to a producer fails CI here
instead of silently re-introducing the 0-record corpus regression. A
functional smoke confirms the producer actually runs offline.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
MAKEFILE = ROOT / "Makefile"
BACKLOG_TOOL = TOOLS / "source-miner-backlog-actions.py"

_FIRM_SCRIPT_RE = re.compile(r"^hackerman-etl-from-audit-firm-pdf-(.+)\.py$")


def _discover_firms() -> list[str]:
    firms: list[str] = []
    for p in sorted(TOOLS.glob("hackerman-etl-from-audit-firm-pdf-*.py")):
        m = _FIRM_SCRIPT_RE.match(p.name)
        if m:
            firms.append(m.group(1))
    return firms


def _load_backlog_module():
    spec = importlib.util.spec_from_file_location(
        "source_miner_backlog_actions", BACKLOG_TOOL
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {BACKLOG_TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FirmEtlWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.firms = _discover_firms()
        # The two original firms plus the 7 W2.4 firms must all be present.
        self.assertGreaterEqual(
            len(self.firms),
            9,
            f"expected >= 9 firm PDF parsers, found {self.firms}",
        )
        for firm in ("pashov", "sb-security", "zellic", "tob",
                     "chainsecurity", "cyfrin", "openzeppelin",
                     "sherlock", "spearbit"):
            self.assertIn(firm, self.firms)
        self.makefile_text = MAKEFILE.read_text(encoding="utf-8", errors="replace")

    def test_every_firm_has_a_non_phony_recipe_target(self) -> None:
        """(b) A real ``<target>:`` recipe line, not merely a .PHONY mention."""
        missing: list[str] = []
        for firm in self.firms:
            target = f"hackerman-etl-from-audit-firm-pdf-{firm}"
            # A recipe target line is at column 0 followed by ':' and is NOT
            # part of a '.PHONY:' declaration.
            recipe_re = re.compile(rf"^{re.escape(target)}\s*:", re.MULTILINE)
            found_recipe = False
            for mobj in recipe_re.finditer(self.makefile_text):
                line_start = self.makefile_text.rfind("\n", 0, mobj.start()) + 1
                line = self.makefile_text[line_start:mobj.start()]
                if not line.lstrip().startswith(".PHONY"):
                    found_recipe = True
                    break
            if not found_recipe:
                missing.append(target)
        self.assertEqual(
            missing,
            [],
            f"firm parsers without a non-phony Makefile recipe target: {missing}",
        )

    def test_every_firm_present_in_backlog_commands(self) -> None:
        """(c) Each firm surfaces as an actionable source-miner refresh command."""
        mod = _load_backlog_module()
        # Backlog families use underscores (sb-security -> sb_security).
        missing = []
        for firm in self.firms:
            family = firm.replace("-", "_")
            if family not in mod.COMMANDS:
                missing.append(family)
        self.assertEqual(
            missing,
            [],
            f"firm families absent from source-miner-backlog COMMANDS: {missing}",
        )

    def test_umbrella_all_target_exists(self) -> None:
        recipe_re = re.compile(
            r"^hackerman-etl-from-audit-firm-pdf-all\s*:", re.MULTILINE
        )
        self.assertTrue(
            recipe_re.search(self.makefile_text),
            "missing umbrella hackerman-etl-from-audit-firm-pdf-all target",
        )

    def test_zellic_producer_runs_offline_and_emits_json(self) -> None:
        """Functional smoke: DRY_RUN + NO_FETCH exits 0 and emits a summary."""
        proc = subprocess.run(
            [
                "make",
                "hackerman-etl-from-audit-firm-pdf-zellic",
                "DRY_RUN=1",
                "NO_FETCH=1",
                "JSON=1",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"producer exited {proc.returncode}; stderr={proc.stderr[-500:]}",
        )
        payload = json.loads(proc.stdout)
        self.assertTrue(payload.get("dry_run"))
        self.assertIn("findings_emitted", payload)


if __name__ == "__main__":
    unittest.main()
