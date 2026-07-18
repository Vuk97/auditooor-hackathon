#!/usr/bin/env python3
"""Regression: the fuzz_campaign_receipt >=1M credit is withheld when the harness no
longer COMPILES against the current source (CUT re-pinned since the recorded run =>
stale evidence). A drifted harness must NOT green the invariant-fuzz floor; a fresh one
still credits; when forge is unavailable (compile verdict None) credit is preserved (no
regression)."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "invariant-fuzz-completeness.py"
_spec = importlib.util.spec_from_file_location("ifc_freshness", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


class TestReceiptFreshness(unittest.TestCase):
    def setUp(self):
        os.environ["AUDITOOOR_INVARIANT_FUZZ_CALLS_STRICT"] = "1"
        self._orig = _m._run_forge_build_contract

    def tearDown(self):
        os.environ.pop("AUDITOOOR_INVARIANT_FUZZ_CALLS_STRICT", None)
        _m._run_forge_build_contract = self._orig

    def _ws(self, name):
        ws = Path(tempfile.mkdtemp())
        aud = ws / ".auditooor"; aud.mkdir(parents=True)
        hd = ws / "chimera_harnesses" / name
        hd.mkdir(parents=True)
        (hd.parent / "foundry.toml").write_text("[profile.default]\nsrc='.'\n")
        (hd / f"{name}.sol").write_text(f"contract {name} {{ function echidna_x() public pure returns(bool){{return true;}} }}")
        (aud / "fuzz_campaign_receipt.json").write_text(json.dumps({"campaigns": [{
            "name": name,
            "harness": f"chimera_harnesses/{name}/{name}.sol",
            "result": {"calls": 1211236}}]}))
        return ws, hd

    def test_drifted_harness_not_credited(self):
        ws, hd = self._ws("DriftedConservation")
        _m._run_forge_build_contract = lambda root, rel: False  # drifted
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 0)

    def test_fresh_harness_credited(self):
        ws, hd = self._ws("FreshConservation")
        _m._run_forge_build_contract = lambda root, rel: True  # compiles
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 1211236)

    def test_unknown_compile_credits_no_regression(self):
        ws, hd = self._ws("UnknownConservation")
        _m._run_forge_build_contract = lambda root, rel: None  # forge absent
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 1211236)

    def test_stale_sha_not_credited_even_if_compiles(self):
        # harness COMPILES now, but the recorded harness_source_sha256 no longer matches
        # the on-disk file => the run predates the current harness (edited since) => stale.
        ws, hd = self._ws("EditedConservation")
        _m._run_forge_build_contract = lambda root, rel: True  # compiles
        rec = ws / ".auditooor" / "fuzz_campaign_receipt.json"
        d = json.loads(rec.read_text())
        d["campaigns"][0]["harness_source_sha256"] = "deadbeef" * 8  # wrong sha
        rec.write_text(json.dumps(d))
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 0)

    def test_matching_sha_credited(self):
        import hashlib
        ws, hd = self._ws("MatchedConservation")
        _m._run_forge_build_contract = lambda root, rel: True
        rec = ws / ".auditooor" / "fuzz_campaign_receipt.json"
        d = json.loads(rec.read_text())
        sol = hd / "MatchedConservation.sol"
        d["campaigns"][0]["harness_source_sha256"] = hashlib.sha256(sol.read_bytes()).hexdigest()
        rec.write_text(json.dumps(d))
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 1211236)

    def test_non_strict_skips_freshness_check(self):
        os.environ.pop("AUDITOOOR_INVARIANT_FUZZ_CALLS_STRICT", None)
        ws, hd = self._ws("LegacyConservation")
        called = {"n": 0}
        def _spy(root, rel):
            called["n"] += 1; return False
        _m._run_forge_build_contract = _spy
        # non-strict: no freshness check runs, legacy credit preserved
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 1211236)
        self.assertEqual(called["n"], 0)


if __name__ == "__main__":
    unittest.main()
