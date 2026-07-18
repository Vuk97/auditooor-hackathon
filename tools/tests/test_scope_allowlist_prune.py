#!/usr/bin/env python3
# <!-- r36-rebuttal: lane SCOPE-ALLOWLIST-PRUNE registered in commit message -->
"""Strata 2026-06-30: the intake over-collected the whole repo into the authoritative
inscope_units.jsonl manifest, leaking OOS files (Strategy/lens/swap) into the worklist.
scope-allowlist-prune intersects the manifest with the SCOPE.md enumerated allowlist.
Pins: prunes OOS rows when an allowlist exists; NOOP (no false prune) when no allowlist.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "scope-allowlist-prune.py"


def _load():
    spec = importlib.util.spec_from_file_location("sap", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["sap"] = m
    spec.loader.exec_module(m)
    return m


sap = _load()

_ENUM_SCOPE = """# SCOPE
## IN SCOPE
1. tranches/Tranche.sol
2. governance/
## OUT OF SCOPE
- 51% attacks
"""
_WHOLE_SCOPE = "# SCOPE\n## In scope\nWhole repo.\n"


def _mk(scope_text, manifest_files):
    ws = Path(tempfile.mkdtemp(prefix="sap_"))
    (ws / "SCOPE.md").write_text(scope_text, encoding="utf-8")
    (ws / ".auditooor").mkdir()
    (ws / ".auditooor" / "inscope_units.jsonl").write_text(
        "".join(json.dumps({"file": f, "name": "f"}) + "\n" for f in manifest_files),
        encoding="utf-8")
    return ws


class ScopeAllowlistPruneTest(unittest.TestCase):
    def test_prunes_oos_under_allowlist(self):
        ws = _mk(_ENUM_SCOPE, [
            "src/contracts/tranches/Tranche.sol",
            "src/contracts/governance/AccessControlManager.sol",
            "src/contracts/tranches/Strategy.sol",      # OOS
            "src/contracts/lens/CDOLens.sol",           # OOS
        ])
        r = sap.prune(ws)
        self.assertEqual(r["verdict"], "pruned")
        self.assertEqual(r["kept"], 2)
        self.assertEqual(r["pruned"], 2)
        remaining = [json.loads(l)["file"] for l in
                     (ws / ".auditooor/inscope_units.jsonl").read_text().splitlines() if l.strip()]
        self.assertTrue(all("Strategy" not in f and "lens" not in f for f in remaining))
        # backup written
        self.assertTrue((ws / ".auditooor/inscope_units.jsonl.preprune.bak").exists())

    def test_noop_without_allowlist(self):
        ws = _mk(_WHOLE_SCOPE, ["src/a/Foo.sol", "src/b/Bar.sol"])
        r = sap.prune(ws)
        self.assertEqual(r["verdict"], "noop-no-allowlist")
        # manifest untouched
        n = len((ws / ".auditooor/inscope_units.jsonl").read_text().strip().splitlines())
        self.assertEqual(n, 2)

    def test_idempotent_already_clean(self):
        ws = _mk(_ENUM_SCOPE, ["src/contracts/tranches/Tranche.sol"])
        sap.prune(ws)
        r2 = sap.prune(ws)
        self.assertIn(r2["verdict"], ("noop-already-clean", "pruned"))
        self.assertEqual(r2["pruned"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
