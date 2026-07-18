#!/usr/bin/env python3
"""Tests for genuine-coverage-sidecar-merge: durable per-fn proofs credit the
genuine_coverage_manifest (the serving-join the recipe was missing)."""
import importlib.util
import json
import os
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "gc_sidecar_merge",
    Path(__file__).resolve().parent.parent / "genuine-coverage-sidecar-merge.py",
)
mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mod)


def _mk_ws(tmp, sidecars, manifest):
    ws = Path(tmp)
    sd = ws / ".auditooor" / "mvc_sidecar"
    sd.mkdir(parents=True, exist_ok=True)
    for name, rec in sidecars.items():
        (sd / name).write_text(json.dumps(rec), encoding="utf-8")
    mpath = ws / ".auditooor" / "genuine_coverage_manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    return ws, mpath


class TestNorm(unittest.TestCase):
    def test_strips_leading_underscore_for_internal_impl(self):
        # internal _bulkRegisterValidator must match facade bulkRegisterValidator
        self.assertEqual(mod._norm_fn("_bulkRegisterValidator"),
                         mod._norm_fn("bulkRegisterValidator"))

    def test_norm_src_drops_dir_line_ext(self):
        self.assertEqual(mod._norm_src("src/ssv/SSVClusters.sol:294"), "ssvclusters")


class TestMerge(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()

    def test_facade_credited_from_module_proof(self):
        # worklist is the SSVNetwork facade; proof is the SSVClusters module fn
        sidecars = {
            "mvc-ssvclusters-deposit.json": {"function": "deposit", "verdict": "non-vacuous"},
        }
        manifest = {
            "verdicts": [
                {"function": "deposit", "source": "SSVNetwork.sol:294", "verdict": "error"},
                {"function": "initialize", "source": "SSVNetwork.sol:43", "verdict": "error"},
            ],
            "counts": {"total": 2, "non_vacuous_genuine": 0, "error": 2},
        }
        ws, mpath = _mk_ws(self.tmp, sidecars, manifest)
        rep = mod.run(ws, mpath)
        self.assertEqual(rep["status"], "ok")
        self.assertIn("deposit", rep["credited"])
        out = json.loads(mpath.read_text())
        dep = [r for r in out["verdicts"] if r["function"] == "deposit"][0]
        self.assertEqual(dep["verdict"], "non-vacuous")
        self.assertEqual(dep["credited_via"], "durable-sidecar")
        self.assertEqual(out["counts"]["non_vacuous_genuine"], 1)
        self.assertEqual(out["mutation_verified_genuine_count"], 1)

    def test_internal_impl_credits_facade_entrypoint(self):
        sidecars = {
            "mvc-ssvvalidators-bulkregistervalidator.json":
                {"function": "_bulkRegisterValidator", "verdict": "non-vacuous"},
        }
        manifest = {
            "verdicts": [
                {"function": "bulkRegisterValidator", "source": "SSVNetwork.sol:246", "verdict": "error"},
            ],
            "counts": {"total": 1, "non_vacuous_genuine": 0, "error": 1},
        }
        ws, mpath = _mk_ws(self.tmp, sidecars, manifest)
        rep = mod.run(ws, mpath)
        self.assertIn("_bulkRegisterValidator", rep["credited"])

    def test_only_non_vacuous_sidecars_credit(self):
        sidecars = {
            "mvc-x-foo.json": {"function": "foo", "verdict": "vacuous"},
        }
        manifest = {"verdicts": [{"function": "foo", "verdict": "error"}], "counts": {}}
        ws, mpath = _mk_ws(self.tmp, sidecars, manifest)
        rep = mod.run(ws, mpath)
        # vacuous sidecar -> no durable proofs to merge
        self.assertEqual(rep["status"], "no-durable-proofs")

    def test_idempotent(self):
        sidecars = {"mvc-c-withdraw.json": {"function": "withdraw", "verdict": "non-vacuous"}}
        manifest = {
            "verdicts": [{"function": "withdraw", "source": "SSVNetwork.sol:302", "verdict": "error"}],
            "counts": {},
        }
        ws, mpath = _mk_ws(self.tmp, sidecars, manifest)
        mod.run(ws, mpath)
        first = json.loads(mpath.read_text())
        rep2 = mod.run(ws, mpath)
        self.assertIn("withdraw", rep2["already_genuine"])
        # load-bearing fields stable across re-run (report block legitimately
        # flips credited->already_genuine, which is meaningful, not a regression)
        second = json.loads(mpath.read_text())
        self.assertEqual(second["verdicts"], first["verdicts"])
        self.assertEqual(second["counts"], first["counts"])
        self.assertEqual(second["mutation_verified_genuine_count"],
                         first["mutation_verified_genuine_count"])

    def test_ambiguous_name_not_false_credited(self):
        # two worklist rows share the name and the sidecar carries no source -> skip
        sidecars = {"mvc-withdraw.json": {"function": "withdraw", "verdict": "non-vacuous"}}
        manifest = {
            "verdicts": [
                {"function": "withdraw", "source": "A.sol", "verdict": "error"},
                {"function": "withdraw", "source": "B.sol", "verdict": "error"},
            ],
            "counts": {},
        }
        ws, mpath = _mk_ws(self.tmp, sidecars, manifest)
        rep = mod.run(ws, mpath)
        self.assertIn("withdraw", rep["ambiguous"])
        out = json.loads(mpath.read_text())
        self.assertTrue(all(r["verdict"] == "error" for r in out["verdicts"]))

    def test_ambiguous_resolved_by_source_basename(self):
        sidecars = {"mvc-ssvclusters-withdraw.json":
                    {"function": "withdraw", "source": "SSVClusters.sol", "verdict": "non-vacuous"}}
        manifest = {
            "verdicts": [
                {"function": "withdraw", "source": "SSVClusters.sol:1", "verdict": "error"},
                {"function": "withdraw", "source": "SSVStaking.sol:9", "verdict": "error"},
            ],
            "counts": {},
        }
        ws, mpath = _mk_ws(self.tmp, sidecars, manifest)
        rep = mod.run(ws, mpath)
        self.assertIn("withdraw", rep["credited"])
        out = json.loads(mpath.read_text())
        clu = [r for r in out["verdicts"] if r["source"].startswith("SSVClusters")][0]
        stk = [r for r in out["verdicts"] if r["source"].startswith("SSVStaking")][0]
        self.assertEqual(clu["verdict"], "non-vacuous")
        self.assertEqual(stk["verdict"], "error")

    def test_unmatched_sidecar_reported(self):
        sidecars = {"mvc-c-ghostfn.json": {"function": "ghostFn", "verdict": "non-vacuous"}}
        manifest = {"verdicts": [{"function": "deposit", "verdict": "error"}], "counts": {}}
        ws, mpath = _mk_ws(self.tmp, sidecars, manifest)
        rep = mod.run(ws, mpath)
        self.assertIn("ghostFn", rep["unmatched_sidecars"])

    def test_opt_out_env(self):
        sidecars = {"mvc-c-deposit.json": {"function": "deposit", "verdict": "non-vacuous"}}
        manifest = {"verdicts": [{"function": "deposit", "verdict": "error"}], "counts": {}}
        ws, mpath = _mk_ws(self.tmp, sidecars, manifest)
        os.environ["AUDITOOOR_GC_NO_SIDECAR_MERGE"] = "1"
        try:
            rep = mod.run(ws, mpath)
            self.assertEqual(rep["status"], "disabled")
        finally:
            del os.environ["AUDITOOOR_GC_NO_SIDECAR_MERGE"]


if __name__ == "__main__":
    unittest.main()
