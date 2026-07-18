#!/usr/bin/env python3
# <!-- r36-rebuttal: lane DATAFLOW-RESOLVE-TARGETS-SCAFFOLDING registered in commit message -->
"""dataflow-slice _resolve_targets must exclude audit-generated scaffolding roots.

Strata 2026-06-30 (R1): a real protocol ws also has foundry.toml under
.auditooor/fuzz_run, chimera_harnesses, and poc-tests/* (harnesses WE authored). The
slice compiled all 11 roots and blew past the timeout before writing a single dataflow
row -> the entire multi-hop dataflow/call-graph capability went dark. Pin: only the real
protocol root(s) resolve.
"""
import importlib.util, sys, tempfile, unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "dataflow-slice.py"
_s = importlib.util.spec_from_file_location("dfslice", _T)
df = importlib.util.module_from_spec(_s); sys.modules["dfslice"] = df; _s.loader.exec_module(df)


class ResolveTargetsScaffoldingTest(unittest.TestCase):
    def test_excludes_audit_scaffolding(self):
        ws = Path(tempfile.mkdtemp(prefix="dfrt_"))
        # the REAL protocol root
        (ws / "src" / "contracts").mkdir(parents=True)
        (ws / "src" / "contracts" / "foundry.toml").write_text("[profile.default]\n")
        # audit-generated scaffolding roots that must NOT be compiled
        for scaffold in (".auditooor/fuzz_run", "chimera_harnesses",
                         "poc-tests/AccountingNav", "poc_execution/x", "prior_audits/old"):
            d = ws / scaffold
            d.mkdir(parents=True)
            (d / "foundry.toml").write_text("[profile.default]\n")
        targets = df._resolve_targets(ws)
        names = {str(t.relative_to(ws)) for t in targets}
        self.assertEqual(names, {"src/contracts"},
                         f"expected only the real protocol root, got {names}")

    def test_real_root_still_resolves(self):
        ws = Path(tempfile.mkdtemp(prefix="dfrt_"))
        (ws / "contracts").mkdir()
        (ws / "foundry.toml").write_text("[profile.default]\n")
        self.assertEqual([t.name for t in df._resolve_targets(ws)], [ws.name])


if __name__ == "__main__":
    unittest.main(verbosity=2)
