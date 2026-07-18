#!/usr/bin/env python3
# <!-- r36-rebuttal: lane COVERAGE-SEED-INSCOPE-FILTER registered in commit message -->
"""Adversarial wiring-verify L8 (2026-06-30): coverage-to-hunt-seed seeds one unhunted-surface
exploit-queue row per uncovered unit, but _enumerate_live_units used the heatmap's
enumerate_units(scope) which keys on scope_globs, NOT the SCOPE.md enumerated allowlist - so
it returned OOS units (Strata: 64 files / 576 rows, 77.8% OOS DYSAccounting/StrataCDO/strategies).
Fix: intersect enumerated units with the authoritative inscope_units.jsonl. Pin: OOS units
dropped; in-scope kept; no manifest -> no filter.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "coverage-to-hunt-seed.py"


def _load():
    spec = importlib.util.spec_from_file_location("c2hs", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["c2hs"] = m
    spec.loader.exec_module(m)
    return m


c2hs = _load()


def _ws(files):
    ws = Path(tempfile.mkdtemp(prefix="c2hs_"))
    (ws / ".auditooor").mkdir()
    if files is not None:
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "".join(json.dumps({"file": f}) + "\n" for f in files), encoding="utf-8")
    return ws


class InscopeFilterTest(unittest.TestCase):
    def test_inscope_bases_reads_manifest(self):
        ws = _ws(["src/contracts/contracts/tranches/Accounting.sol",
                  "src/contracts/contracts/tranches/utils/RoundingGuard.sol"])
        bases = c2hs._inscope_file_bases(ws)
        self.assertEqual(bases, {"Accounting.sol", "RoundingGuard.sol"})

    def test_no_manifest_empty(self):
        ws = _ws(None)
        self.assertEqual(c2hs._inscope_file_bases(ws), set())

    def test_unit_basename_intersection_drops_oos(self):
        # mimic the filter: in-scope Accounting kept, OOS DYSAccounting/StrataCDO dropped
        inscope = {"Accounting.sol"}
        units = {
            "src/contracts/contracts/tranches/Accounting.sol::deposit",
            "src/contracts/contracts/tranches/DYSAccounting.sol::foo",
            "src/contracts/contracts/tranches/StrataCDO.sol::bar",
        }
        kept = {u for u in units if c2hs._unit_basename(u) in inscope}
        self.assertEqual(kept, {"src/contracts/contracts/tranches/Accounting.sol::deposit"})



    def test_seed_from_report_prunes_oos_unhunted_rows(self):
        # an existing queue with OOS unhunted-surface rows must be pruned on re-seed
        import json, tempfile
        from pathlib import Path
        ws = Path(tempfile.mkdtemp(prefix="c2hs_"))
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/contracts/contracts/tranches/Accounting.sol"}) + "\n",
            encoding="utf-8")
        qp = ws / ".auditooor" / "exploit_queue.json"
        qp.write_text(json.dumps({"schema": "auditooor.exploit_queue.v1", "queue": [
            {"source": "unhunted-surface", "file": "Accounting.sol", "unit_id": "Accounting.sol::deposit"},
            {"source": "unhunted-surface", "file": "DYSAccounting.sol", "unit_id": "DYSAccounting.sol::foo"},
            {"source": "corpus-hunt-fuel", "file": "DiscreteAccounting.sol", "unit_id": "x"},
        ]}), encoding="utf-8")
        report = {"workspace_name": "t", "workspace": str(ws), "uncovered_units": [],
                  "uncovered": 0, "enumeration": {"source_root": str(ws)}}
        c2hs.seed_from_report(report, qp, dry_run=False, workspace_path=ws)
        rows = json.loads(qp.read_text())["queue"]
        srcs = [(r.get("source"), r.get("file")) for r in rows]
        # OOS unhunted-surface DYSAccounting dropped; in-scope Accounting kept; foreign corpus-hunt preserved
        self.assertNotIn(("unhunted-surface", "DYSAccounting.sol"), srcs)
        self.assertIn(("corpus-hunt-fuel", "DiscreteAccounting.sol"), srcs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
