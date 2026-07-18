#!/usr/bin/env python3
"""test_completeness_matrix_mvc_source_file_join.py

SERVING-JOIN regression (SSV 2026-07-03): the per-file completeness-matrix mvc
reader `_mvc_asset_invariant_categories` only credited a sidecar that carried the
literal `mutation_verified: true` flag AND stored its CUT under
cut/cut_files/match_path/contract/harness_path. The per-FUNCTION mutation-verify
producer (tools/mutation-verify-coverage.py + its --register-manual-mvc path)
instead records its non-vacuity witness as `verdict: "non-vacuous"` +
`behavior_changing_kill_count >= 1` and stores the module-under-test under
`source_file` (as an ABSOLUTE path). So a GENUINE per-function mutation-verify
run (e.g. SSVDAO.commitRoot / SSVValidators.registerValidator, 6 behavior-changing
kills each) was INVISIBLE to the per-file floor - the evidence was on disk but the
reader keyed on the wrong fields (absence-is-invisible false-red).

The fix credits such a sidecar (source_file CUT + non-vacuous verdict + a real
behavior-changing kill), relativizing the absolute source_file to the workspace.
NEVER-FALSE-PASS: a sidecar with no mutation_verified flag AND no genuine
behavior-changing kill (survived / vacuous / panic-only) still credits nothing.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"


def _load():
    spec = importlib.util.spec_from_file_location("completeness_matrix_build", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["completeness_matrix_build"] = m
    spec.loader.exec_module(m)
    return m


class TestMvcSourceFileJoin(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws_with_sidecar(self, tmp: Path, sidecar: dict) -> Path:
        ws = tmp / "ws"
        (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        (ws / ".auditooor" / "mvc_sidecar" / "s.json").write_text(
            json.dumps(sidecar), encoding="utf-8")
        return ws

    def test_nonvacuous_kill_source_file_credits_perfile(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src_abs = tmp / "ws" / "src" / "repo" / "contracts" / "Mod.sol"
            ws = self._ws_with_sidecar(tmp, {
                "source_file": str(src_abs),         # ABSOLUTE, as the producer writes
                "verdict": "non-vacuous",
                "behavior_changing_kill_count": 6,
                "invariants": [],                    # per-fn sidecars carry no invariants array
            })
            out = self.m._mvc_asset_invariant_categories(
                ws, asset_key=self.m._perfile_asset_of, credit_empty_invariants=True)
            # the RELATIVE per-file key must be credited (not the absolute path, not the harness)
            self.assertIn("src/repo/contracts/Mod.sol", out,
                          f"genuine non-vacuous per-fn sidecar not credited: {out}")
            self.assertIn("conservation", out["src/repo/contracts/Mod.sol"])

    def test_survived_only_sidecar_credits_nothing(self):
        # never-false-pass: no mutation_verified flag AND no behavior-changing kill
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src_abs = tmp / "ws" / "src" / "repo" / "contracts" / "Mod.sol"
            ws = self._ws_with_sidecar(tmp, {
                "source_file": str(src_abs),
                "verdict": "vacuous",
                "behavior_changing_kill_count": 0,
                "invariants": [],
            })
            out = self.m._mvc_asset_invariant_categories(
                ws, asset_key=self.m._perfile_asset_of, credit_empty_invariants=True)
            self.assertEqual(out, {}, f"a survived/vacuous sidecar must credit nothing: {out}")

    def test_nonvacuous_without_kill_credits_nothing(self):
        # verdict says non-vacuous but zero behavior-changing kills -> not a genuine witness
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src_abs = tmp / "ws" / "src" / "repo" / "contracts" / "Mod.sol"
            ws = self._ws_with_sidecar(tmp, {
                "source_file": str(src_abs),
                "verdict": "non-vacuous",
                "behavior_changing_kill_count": 0,
                "invariants": [],
            })
            out = self.m._mvc_asset_invariant_categories(
                ws, asset_key=self.m._perfile_asset_of, credit_empty_invariants=True)
            self.assertEqual(out, {}, f"non-vacuous with 0 kills must credit nothing: {out}")

    def test_legacy_mutation_verified_flag_still_credits(self):
        # backward-compat: the original mutation_verified:true campaign path is unchanged
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = self._ws_with_sidecar(tmp, {
                "mutation_verified": True,
                "cut_files": ["src/repo/contracts/HarnessMedusa.sol"],
                "invariants": [{"id": "INV-1", "name": "conservation sum-preserved"}],
            })
            out = self.m._mvc_asset_invariant_categories(ws)  # legacy per-repo asset_key
            self.assertTrue(out, "legacy mutation_verified sidecar must still credit")


if __name__ == "__main__":
    unittest.main()
