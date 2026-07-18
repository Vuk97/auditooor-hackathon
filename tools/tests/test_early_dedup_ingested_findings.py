#!/usr/bin/env python3
"""Regression: early-prior-audit-dedup-gate.py scans prior_audits/INGESTED_FINDINGS.md
(the curated 'class #N ... COVERED' dedup list) so a candidate landing in an
already-COVERED prior-audit class is flagged BEFORE hunt/PoC investment - not only at
pre-submit R47/R53. Strata 2026-07-07: DiscreteAccounting.calculateNAVSplitProjected sat
inside covered class #4 'senior/junior nav reconciliation' but INGESTED_FINDINGS.md was
unscanned, so a full hunt + 2 PoCs were spent before dedup fired."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "early-prior-audit-dedup-gate.py"
_spec = importlib.util.spec_from_file_location("early_dedup", _MOD)
_m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _m
_spec.loader.exec_module(_m)


class TestEarlyDedupIngested(unittest.TestCase):
    def _ws(self):
        ws = Path(tempfile.mkdtemp())
        pa = ws / "prior_audits"
        pa.mkdir()
        (pa / "INGESTED_FINDINGS.md").write_text(
            "# Prior findings\n\n"
            "| M-5 | Medium | calculateNavSplitProjected seniorTargetGain reconciliation "
            "sum mismatch is acknowledged by-design and Resolved in the prior audit |\n"
            "## Dedup Summary - classes already COVERED\n"
            "4. calculateNavSplitProjected seniorTargetGain reconciliation: acknowledged, "
            "COVERED unless extension-distinct.\n")
        return ws

    def test_ingested_findings_is_scanned(self):
        ws = self._ws()
        files = _m._prior_audit_files(ws)
        self.assertTrue(any(f.name == "INGESTED_FINDINGS.md" for f in files))

    def test_covered_class_candidate_matched_from_ingested(self):
        # THE fix: a candidate sharing distinctive tokens with INGESTED_FINDINGS.md now
        # gets a match FROM that file (previously it was unscanned -> zero evidence ->
        # silent pass). Escalation to KILLED/NEEDS-EXTENSION-DISTINCT is the gate's
        # existing ack-proximity logic (verified on the real Strata file -> KILLED).
        ws = self._ws()
        res = _m.run_gate(ws, ["calculateNavSplitProjected", "seniorTargetGain", "reconciliation"],
                          title="calculateNavSplitProjected seniorTargetGain reconciliation")
        scanned = [Path(f).name for f in res.get("files_scanned", [])]
        self.assertIn("INGESTED_FINDINGS.md", scanned)
        # the file contributed evidence (weak or strong) - it is no longer invisible
        contributed = res.get("weak_evidence_count", 0) >= 1 or len(res.get("strong_evidence", [])) >= 1
        self.assertTrue(contributed,
                        f"INGESTED_FINDINGS.md should contribute a dedup match; res={res.get('reason')}")

    def test_novel_candidate_passes(self):
        ws = self._ws()
        res = _m.run_gate(ws, ["xyzzy", "frobnicate", "zzznovel"],
                          title="xyzzy frobnicate zzznovel")
        self.assertEqual(res["verdict"], "pass",
                         f"novel candidate should pass, got {res['verdict']}")


if __name__ == "__main__":
    unittest.main()
