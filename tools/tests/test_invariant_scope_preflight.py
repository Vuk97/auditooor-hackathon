#!/usr/bin/env python3
"""Regression: invariant-scope-preflight classifies candidate invariant-fuzz lane assets
on scope/known-findings axes BEFORE investment, and its AUTHORITATIVE OOS exemption is
consumed by invariant-fuzz-completeness._asset_coverage (drops OOS files from gaps with a
cite) while REVIEW_DEDUP stays a gap (never auto-exempt-away real surface).

Operator 2026-07-07: "match invariants against OOS / known findings / what makes them
in-scope, as a generic enforcement" - so we stop fuzzing OOS/disclosed surface (coverage
theater) yet never green a gate by hand."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent


def _load(name, fn):
    s = importlib.util.spec_from_file_location(name, _H.parent / fn)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


pf = _load("isp", "invariant-scope-preflight.py")
ifc = _load("ifc", "invariant-fuzz-completeness.py")


class T(unittest.TestCase):
    def _ws(self, vm_files, inscope_files, prior=None, filed=None):
        ws = Path(tempfile.mkdtemp())
        a = ws / ".auditooor"
        a.mkdir(parents=True)
        (a / "value_moving_functions.json").write_text(json.dumps(
            {"functions": [{"file": f, "transfer_hit": True} for f in vm_files]}))
        (a / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps({"file": f, "function": "f"}) for f in inscope_files))
        if prior is not None:
            (ws / "prior_audits").mkdir(exist_ok=True)
            (ws / "prior_audits" / "known_issues.jsonl").write_text(
                "\n".join(json.dumps(r) for r in prior))
        if filed is not None:
            for name, body in filed.items():
                d = ws / "submissions" / "paste_ready" / "filed" / name
                d.mkdir(parents=True)
                (d / f"{name}.md").write_text(body)
        return ws

    def test_oos_file_is_auto_exempt_and_dropped_from_gaps(self):
        # Foo in-scope + value-moving but NOT in the inscope manifest -> scope_authority
        # says OOS -> EXEMPT_OOS -> dropped from invariant-fuzz gaps with a cite.
        ws = self._ws(vm_files=["src/InScope.sol", "src/Oos.sol"],
                      inscope_files=["src/InScope.sol"])  # Oos.sol NOT in manifest
        r = pf.check(ws)
        cls = {a["asset"].split("/")[-1]: a["classification"] for a in r["assets"]}
        self.assertEqual(cls.get("Oos.sol"), "EXEMPT_OOS")
        self.assertIn("src/Oos.sol", r["exempt_oos_files"])
        # the gate's own in-scope vm already excludes Oos.sol, so it is never a gap; the
        # scope_exempt branch is the safety net for the source-scan-adds-OOS edge only.
        (ws / ".auditooor" / "invariant_scope_preflight.json").write_text(json.dumps(r))
        cov = ifc._asset_coverage(ws, [])
        self.assertNotIn("src/Oos.sol", cov["gaps"])

    def test_prior_finding_is_review_dedup_not_exempt(self):
        # An asset with a prior-audit finding is REVIEW_DEDUP (advisory) - it STAYS a gap
        # (never auto-exempt-away real surface), only annotated for dedup-before-invest.
        ws = self._ws(vm_files=["src/Accounting.sol"], inscope_files=["src/Accounting.sol"],
                      prior=[{"id": "M-12", "file": "Accounting.sol", "severity": "Medium",
                              "status": "resolved", "dedup_class": "apr"}])
        r = pf.check(ws)
        self.assertEqual(r["assets"][0]["classification"], "REVIEW_DEDUP")
        (ws / ".auditooor" / "invariant_scope_preflight.json").write_text(json.dumps(r))
        cov = ifc._asset_coverage(ws, [])
        self.assertIn("src/Accounting.sol", cov["gaps"])            # still a gap
        self.assertIn("src/Accounting.sol", cov["gaps_needing_dedup_review"])  # flagged

    def test_clean_inscope_asset_requires_lane(self):
        ws = self._ws(vm_files=["src/Clean.sol"], inscope_files=["src/Clean.sol"])
        r = pf.check(ws)
        self.assertEqual(r["assets"][0]["classification"], "REQUIRES_LANE")
        self.assertTrue(r["assets"][0]["requires_lane"])

    def test_filed_mention_is_review_dedup(self):
        ws = self._ws(vm_files=["src/sNUSDCooldownRequestImpl.sol"],
                      inscope_files=["src/sNUSDCooldownRequestImpl.sol"],
                      filed={"freeze": "affected: `sNUSDCooldownRequestImpl.sol:34-48` guard"})
        r = pf.check(ws)
        self.assertEqual(r["assets"][0]["classification"], "REVIEW_DEDUP")
        self.assertEqual(len(r["assets"][0]["filed_mentions"]), 1)


if __name__ == "__main__":
    unittest.main()
