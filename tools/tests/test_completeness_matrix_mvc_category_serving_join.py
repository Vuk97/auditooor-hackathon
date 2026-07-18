#!/usr/bin/env python3
"""test_completeness_matrix_mvc_category_serving_join.py

SERVING-JOIN + per-file JOIN over-strictness regression (NUVA 2026-07-04).

Three fixes in completeness-matrix-build.py, all in the invariant-axis reader /
worklist tagger, all FALSE-GREEN-SAFE (gated on a mutation-verified / behavior-
changing-kill sidecar; a survived / vacuous run still credits nothing):

  (A) _mvc_asset_invariant_categories reads the invariant object's FULL semantic
      label - id + name + property_fn + description + subsystem - not just
      id+name+property_fn. The category language of a mutation-verified invariant
      often lives in description/subsystem (e.g. "an ATOMIC deposit->redeem round
      trip" -> atomicity; subsystem "...access-control (state-machine)" -> ordering),
      so reading the narrow subset left genuinely-proven categories NOT-ENUMERATED.

  (B) The descriptive frame text (contract / cut_fn / kill_invariant_frame) is folded
      into the cue text for a sidecar that HAS a non-empty invariants array too (not
      only for the empty-invariants branch). Category language often lives in the
      mutant frame ("owner must regain exactly the escrowed shares" -> custody) that
      the terse invariant id/name omits. The empty-invariants branch still only
      credits under the strict per-file caller (backward-compat preserved).

  (C) build_enumeration_worklist demotes a COVERED per-FILE asset's residual
      invariant-category rows to dropped_nonentry. A single source file does not span
      all 10 CANONICAL_INVARIANT_CATEGORIES (a token file has no custody invariant, a
      router no monotonicity), so demanding every category on every file was a
      structurally-unsatisfiable over-strictness. GATED to per-FILE grouping: a
      per-REPO asset (spanning all 10 classes) still owes every canonical category, so
      the per-repo invariant-enum JOIN is unchanged. FAIL-CLOSED: a file with ZERO
      enumerated categories stays value_moving.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"


def _load():
    spec = importlib.util.spec_from_file_location("completeness_matrix_build_sj", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["completeness_matrix_build_sj"] = m
    spec.loader.exec_module(m)
    return m


class TestMvcCategoryServingJoin(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, tmp: Path, sidecar: dict) -> Path:
        ws = tmp / "ws"
        (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        (ws / ".auditooor" / "mvc_sidecar" / "s.json").write_text(
            json.dumps(sidecar), encoding="utf-8")
        return ws

    # -- Fix A: description/subsystem carry the category cue -------------------
    def test_description_subsystem_fold_credits_category(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._ws(Path(td), {
                "mutation_verified": True,
                "cut_files": ["src/repo/contracts/Vault.sol"],
                # id/name/property_fn carry NO category cue; description carries
                # 'atomic', subsystem carries 'state-machine' (ordering).
                "invariants": [{
                    "id": "INV-1", "name": "no_free_roundtrip",
                    "property_fn": "property_no_free_roundtrip",
                    "description": "an ATOMIC deposit->redeem round trip returns <= x",
                    "subsystem": "Vault rotation access-control (state-machine)",
                }],
            })
            out = self.m._mvc_asset_invariant_categories(ws)
            cats = out.get("src/repo", set())
            self.assertIn("atomicity", cats,
                          f"description 'atomic' must credit atomicity: {cats}")
            self.assertIn("ordering", cats,
                          f"subsystem 'state-machine' must credit ordering: {cats}")

    # -- Fix B: non-empty-invariants sidecar also folds the mutant frame -------
    def test_nonempty_invariants_sidecar_folds_mutant_frame(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._ws(Path(td), {
                "mutation_verified": True,
                "cut_files": ["src/repo/keeper/payout.go"],
                # invariant id/name carry no custody cue; the mutant frame does.
                "invariants": [{"id": "INV-CON-1", "name": "conservation_ok"}],
                "mutant_results": [{
                    "killed": True, "kill_kind": "behavior-changing",
                    "kill_invariant_frame": "refund: owner must regain exactly the escrowed shares",
                }],
            })
            out = self.m._mvc_asset_invariant_categories(ws)
            cats = out.get("src/repo", set())
            self.assertIn("custody", cats,
                          f"mutant frame 'escrowed shares' must credit custody: {cats}")

    def test_survived_run_still_credits_nothing(self):
        # never-false-pass: not mutation_verified AND no behavior-changing kill
        with tempfile.TemporaryDirectory() as td:
            ws = self._ws(Path(td), {
                "verdict": "vacuous",
                "behavior_changing_kill_count": 0,
                "cut_files": ["src/repo/contracts/Vault.sol"],
                "invariants": [{
                    "id": "INV-1", "name": "x",
                    "description": "an ATOMIC round trip", "subsystem": "state-machine",
                }],
            })
            out = self.m._mvc_asset_invariant_categories(ws)
            self.assertEqual(out, {}, f"a survived/vacuous sidecar credits nothing: {out}")

    # -- Fix C: per-file covered-file residual categories are dropped_nonentry -
    def _matrix_with_asset(self, grouping: str, enum_count: int):
        # Minimal matrix dict shaped like build_matrix output for the worklist tagger.
        not_enum = [c for c in self.m.CANONICAL_INVARIANT_CATEGORIES][enum_count:]
        return {
            "denominators": {"asset_grouping": grouping},
            "assets": [{
                "asset_id": "src/repo/contracts/CustomToken.sol",
                "functions": [],
                "invariant_categories_enumerated": enum_count,
                "invariant_categories_not_enumerated": not_enum,
                "all_nonentry": False, "has_real_function": True,
                "file_dispositioned": False,
            }],
        }

    def test_perfile_covered_file_residual_categories_dropped(self):
        # per-FILE grouping + a COVERED file (2/10 categories enumerated): the 8
        # residual category rows must be dropped_nonentry (not value_moving).
        m = self._matrix_with_asset("per-file", enum_count=2)
        rows = self.m.build_enumeration_worklist(m)
        inv_rows = [r for r in rows if r.get("axis") == "invariant"]
        self.assertTrue(inv_rows, "expected residual invariant rows to be emitted")
        vm = [r for r in inv_rows if r.get("cell_kind") == "value_moving"]
        self.assertEqual(vm, [],
                         f"covered per-file residual categories must be dropped_nonentry: {vm}")

    def test_perfile_zero_coverage_file_stays_value_moving(self):
        # FAIL-CLOSED: a per-file asset with ZERO enumerated categories is a genuine
        # coverage gap and stays value_moving (a real obligation).
        m = self._matrix_with_asset("per-file", enum_count=0)
        rows = self.m.build_enumeration_worklist(m)
        vm = [r for r in rows if r.get("axis") == "invariant"
              and r.get("cell_kind") == "value_moving"]
        self.assertEqual(len(vm), len(self.m.CANONICAL_INVARIANT_CATEGORIES),
                         f"a zero-coverage per-file asset stays a value_moving obligation: {vm}")

    def test_perrepo_partial_coverage_stays_value_moving(self):
        # The per-repo JOIN (the invariant-enum lane's target) is UNCHANGED: a
        # per-REPO asset with partial coverage still owes its residual categories.
        m = self._matrix_with_asset("per-repo", enum_count=6)
        m["assets"][0]["asset_id"] = "src/repo"  # a per-repo asset id, not a file path
        rows = self.m.build_enumeration_worklist(m)
        vm = [r for r in rows if r.get("axis") == "invariant"
              and r.get("cell_kind") == "value_moving"]
        self.assertEqual(len(vm), 4,
                         f"per-repo partial coverage must still red the 4 residual categories: {vm}")


if __name__ == "__main__":
    unittest.main()
