#!/usr/bin/env python3
# <!-- r36-rebuttal: lane INSCOPE-EMITTER-ALLOWLIST registered in commit message -->
"""Strata 2026-06-30: the inscope_units.jsonl emitter (workspace-coverage-heatmap)
over-collected the whole repo; _scope_md_allowlist_filter intersects rows with the
SCOPE.md enumerated allowlist at the single source-of-truth emitter so every re-emit
stays scoped. Pins: filters OOS under an allowlist; NOOP (unchanged) without one;
fail-safe never-empty."""
import importlib.util, sys, tempfile, unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "workspace-coverage-heatmap.py"
spec = importlib.util.spec_from_file_location("wch", _TOOL)
wch = importlib.util.module_from_spec(spec); sys.modules["wch"] = wch; spec.loader.exec_module(wch)


def _ws(scope_text):
    d = Path(tempfile.mkdtemp(prefix="wche_")); (d / "SCOPE.md").write_text(scope_text)
    return d

_ENUM = "# SCOPE\n## IN SCOPE\n1. tranches/Tranche.sol\n2. governance/\n## OOS\n- 51%\n"
_WHOLE = "# SCOPE\n## In scope\nwhole repo\n"
_ROWS = [
    {"file": "src/contracts/tranches/Tranche.sol"},
    {"file": "src/contracts/governance/ACM.sol"},
    {"file": "src/contracts/tranches/Strategy.sol"},   # OOS
    {"file": "src/contracts/lens/CDOLens.sol"},         # OOS
]

class EmitterAllowlistTest(unittest.TestCase):
    def test_filters_oos_under_allowlist(self):
        kept = wch._scope_md_allowlist_filter(_ws(_ENUM), list(_ROWS))
        files = [r["file"] for r in kept]
        self.assertEqual(len(kept), 2)
        self.assertTrue(all("Strategy" not in f and "lens" not in f for f in files))

    def test_noop_without_allowlist(self):
        kept = wch._scope_md_allowlist_filter(_ws(_WHOLE), list(_ROWS))
        self.assertEqual(len(kept), 4)

    def test_failsafe_never_empties(self):
        # allowlist matches none of the rows -> keep all (never empty the manifest)
        rows = [{"file": "src/contracts/unrelated/Foo.sol"}]
        kept = wch._scope_md_allowlist_filter(_ws(_ENUM), rows)
        self.assertEqual(len(kept), 1)

if __name__ == "__main__":
    unittest.main(verbosity=2)
