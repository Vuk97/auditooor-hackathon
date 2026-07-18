"""Regression: executed-refutation gate credits a genuine poc_execution_record via
its SOURCE anchor + the canonical .auditooor/ path (2026-07-14).

Two serving-join gaps fixed together:
  1. collect_poc_records only globbed ws/poc_execution/ - a manifest at the CANONICAL
     ws/.auditooor/poc_execution/ (where the runbook + spawn-worker write it, like the
     mvc_sidecar arm) was invisible.
  2. the poc_execution arm tokenized only candidate_id/brief/poc_dir ("abci" != the
     unit's "abci.go" basename), so it could never JOIN a real executed refutation to
     the value-mover NEGATIVE on that source file. Now indexes source_refs/cut/
     file_line source-file basenames (extension-gated) + the function name.
"""
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "executed-refutation-negative-gate.py"
_spec = importlib.util.spec_from_file_location("_err_gate", _TOOL)
_m = importlib.util.module_from_spec(_spec)
sys.modules["_err_gate"] = _m
_spec.loader.exec_module(_m)


class ExecutedRefutationPocSourceAnchor(unittest.TestCase):
    def _write_manifest(self, ws, subdir, obj):
        d = pathlib.Path(ws) / ".auditooor" / "poc_execution" / subdir
        d.mkdir(parents=True, exist_ok=True)
        (d / "execution_manifest.json").write_text(json.dumps(obj))

    def test_canonical_path_and_source_anchor_credit(self):
        with tempfile.TemporaryDirectory() as ws:
            self._write_manifest(ws, "abci_conservation", {
                "candidate_id": "abci-beginblock-conservation",
                "source_refs": ["src/vault/keeper/abci.go:19"],
                "function": "BeginBlocker",
                "commands_attempted": [{"cmd": "go test ...", "status": "pass", "exit_code": 0}],
                "impact_notes": "misroute mutant kills the conservation assertion",
            })
            recs = _m.collect_poc_records(ws)
            self.assertTrue(recs, "manifest at .auditooor/poc_execution/ must be found")
            r = recs[0]
            self.assertIn("abci.go", r["tokens"],
                          "source_refs file basename must be indexed as a match token")
            self.assertTrue(r["executed"], "commands_attempted pass -> executed")
            self.assertTrue(r["guard_neutralized"], "'mutant kills' -> guard-neutralized")
            # the abci.go value-mover NEGATIVE now JOINs this executed refutation
            unit_toks = _m._unit_tokens({"source_refs": ["src/vault/keeper/abci.go:19"],
                                         "mechanism": "funding-rate-manipulation"})
            self.assertIsNotNone(_m._match_poc(unit_toks, recs),
                                 "abci.go NEGATIVE must match the abci.go executed poc")

    def test_no_source_anchor_no_spurious_credit(self):
        # a manifest with only generic tokens (no source_refs / fn) must NOT match an
        # unrelated unit - anti-over-credit preserved.
        with tempfile.TemporaryDirectory() as ws:
            self._write_manifest(ws, "generic", {
                "candidate_id": "vault",  # generic, dropped
                "commands_attempted": [{"status": "pass", "exit_code": 0}],
                "impact_notes": "mutant killed",
            })
            recs = _m.collect_poc_records(ws)
            unit_toks = _m._unit_tokens({"source_refs": ["src/vault/keeper/payout.go:1"]})
            self.assertIsNone(_m._match_poc(unit_toks, recs),
                              "a generic-only poc must not spuriously credit payout.go")


if __name__ == "__main__":
    unittest.main()
