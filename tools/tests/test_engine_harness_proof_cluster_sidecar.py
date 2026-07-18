"""Loop-fix 2026-06-23 (etherfi step-5/engine-harness): engine-harness-proof-check
credited mutation-verified harnesses from `.auditooor/mvc_sidecar/*.json` ONLY when the
record used the flat mutation_verify_coverage.v1 schema (verdict=="non-vacuous") with an
ABSOLUTE harness_path on disk. The durable mvc_sidecar CLUSTER schema (mutation_verified
+ mutants_killed + result, ws-RELATIVE harness_path) matched neither check, so genuine
>=1M-call mutation-verified Chimera harnesses (etherfi LiquidRestaking/CashSolvency) were
classified fail-stub-or-ghost by the static classify_path heuristic -> fail-no-proven-
harness despite real non-vacuous campaigns. Same serving-join delivery bug as the core-
coverage cluster-sidecar fix.

Fix: _record_is_nonvacuous accepts both schemas; the mvc_sidecar loop resolves a ws-
relative harness_path against the workspace; and _campaign_sol_siblings credits the whole
campaign bundle (harness + sibling .t.sol) so a non-vacuous campaign is not vetoed by its
own foundry test file. False-green-safe: a vacuous (0-kill) cluster credits nothing, and a
record whose harness_path is absent from disk is skipped.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("ehp", str(_TOOLS / "engine-harness-proof-check.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ehp"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestEngineHarnessProofClusterSidecar(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp()).resolve()
        # a genuine campaign tree: harness + sibling foundry test
        camp = self.ws / "chimera_harnesses" / "CashSolvency"
        (camp / "src").mkdir(parents=True)
        (camp / "test").mkdir(parents=True)
        (camp / "src" / "CashSolvencyHarness.sol").write_text("contract H{ function property_x() public returns(bool){} }")
        (camp / "test" / "CashSolvency.t.sol").write_text("contract T{ function invariant_x() public {} }")
        (self.ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)

    def _write(self, name, payload):
        (self.ws / ".auditooor" / "mvc_sidecar" / name).write_text(json.dumps(payload))

    def test_record_is_nonvacuous_accepts_cluster_schema(self):
        self.assertTrue(self.m._record_is_nonvacuous({"mutation_verified": True, "mutants_killed": 4}))
        self.assertTrue(self.m._record_is_nonvacuous(
            {"mutation_verified": True, "mutation_detail": [{"mutant_result": "FAIL"}]}))
        self.assertTrue(self.m._record_is_nonvacuous({"verdict": "non-vacuous"}))
        # vacuous / no-kill -> False
        self.assertFalse(self.m._record_is_nonvacuous({"mutation_verified": True, "mutants_killed": 0}))
        self.assertFalse(self.m._record_is_nonvacuous({"result": "honest-negative"}))

    def test_cluster_sidecar_credits_whole_campaign_bundle(self):
        self._write("cash_solvency.json", {
            "cluster": "CashSolvency", "mutation_verified": True, "mutants_killed": 4,
            "harness_path": "chimera_harnesses/CashSolvency/src/CashSolvencyHarness.sol",
            "mutation_detail": [{"mutant": "DebtManagerCore repay 2x", "mutant_result": "FAIL"}],
            "result": "honest-negative",
        })
        proven = self.m._mutation_verified_harnesses(self.ws)
        # both the named harness AND its sibling .t.sol are credited
        names = {Path(p).name for p in proven}
        self.assertIn("CashSolvencyHarness.sol", names)
        self.assertIn("CashSolvency.t.sol", names)

    def test_vacuous_cluster_credits_nothing(self):
        self._write("vacuous.json", {
            "cluster": "CashSolvency", "mutation_verified": True, "mutants_killed": 0,
            "harness_path": "chimera_harnesses/CashSolvency/src/CashSolvencyHarness.sol",
            "result": "honest-negative",
        })
        self.assertEqual(self.m._mutation_verified_harnesses(self.ws), set())

    def test_missing_harness_file_credits_nothing(self):
        self._write("ghost.json", {
            "cluster": "Ghost", "mutation_verified": True, "mutants_killed": 3,
            "harness_path": "chimera_harnesses/DoesNotExist/H.sol",
        })
        self.assertEqual(self.m._mutation_verified_harnesses(self.ws), set())

    # --- 2026-06-23 SSV loop fix: harness_path outside the _discover globs ----
    # The mvc_sidecar may name the REAL src/.../test/echidna proof while _discover
    # only globs chimera_harnesses/ (a byte-identical COPY). The two paths never
    # matched -> the static heuristic vetoed both as fail-stub-or-ghost. Fixed via
    # (a) _mvc_named_harness_paths direct injection, (b) content-hash crediting of
    # the discovered copy, (c) _record_is_nonvacuous accepting a mutation_verify[]
    # array of KILLED rows (the cluster-schema variant SSVEBAccounting uses).

    def test_record_is_nonvacuous_accepts_mutation_verify_array(self):
        self.assertTrue(self.m._record_is_nonvacuous(
            {"mutation_verify": [{"mutant_id": "A", "verdict": "KILLED"}]}))
        self.assertTrue(self.m._record_is_nonvacuous(
            {"mutation_verify": [{"mutant_id": "A", "verdict": "survived"},
                                 {"mutant_id": "B", "verdict": "KILLED"}]}))
        # no KILLED row -> vacuous
        self.assertFalse(self.m._record_is_nonvacuous(
            {"mutation_verify": [{"mutant_id": "A", "verdict": "survived"}]}))

    def test_named_harness_path_outside_discovery_globs_is_proven(self):
        # harness lives under src/.../test/echidna (NOT a _discover glob); only the
        # mvc_sidecar names it. It must still be credited proven, not dropped.
        import shutil
        shutil.rmtree(self.ws / "chimera_harnesses", ignore_errors=True)  # drop setUp stub campaign
        real = self.ws / "src" / "repo" / "test" / "echidna"
        real.mkdir(parents=True)
        hp = real / "RealInvariant.sol"
        hp.write_text("contract H{ function property_x() public returns(bool){ return a<=b; } }")
        self._write("real.json", {
            "cluster": "Real", "mutation_verified": True, "mutants_killed": 2,
            "harness_path": "src/repo/test/echidna/RealInvariant.sol",
        })
        named = self.m._mvc_named_harness_paths(self.ws)
        self.assertIn(str(hp.resolve()), named)
        res = self.m.evaluate(self.ws)
        self.assertTrue(str(res["verdict"]).startswith("pass"), res)
        self.assertIn("src/repo/test/echidna/RealInvariant.sol", res["proven"])

    def test_byte_identical_copy_inherits_proven_via_content_hash(self):
        # the genuine proof lives at src/...; a byte-identical COPY sits under
        # chimera_harnesses/ (which _discover finds + classify_path would veto).
        import shutil
        shutil.rmtree(self.ws / "chimera_harnesses", ignore_errors=True)  # drop setUp stub campaign
        body = "contract H{ function property_x() public returns(bool){ return totalOut<=totalIn; } }"
        real = self.ws / "src" / "repo" / "test" / "echidna"
        real.mkdir(parents=True)
        (real / "Cov.sol").write_text(body)
        copy = self.ws / "chimera_harnesses" / "Cov"
        copy.mkdir(parents=True)
        (copy / "Cov.sol").write_text(body)  # byte-identical copy
        self._write("cov.json", {
            "cluster": "Cov", "mutation_verified": True, "mutants_killed": 1,
            "harness_path": "src/repo/test/echidna/Cov.sol",
        })
        res = self.m.evaluate(self.ws)
        self.assertEqual(res["verdict"], "pass-engine-harness-proof", res)
        self.assertEqual(res["unproven"], [], res)
        # the chimera copy is credited (not vetoed) by content-hash match
        self.assertIn("chimera_harnesses/Cov/Cov.sol", res["proven"])


class TestEngineHarnessProofV1FlatSchemaNoHarnessPath(unittest.TestCase):
    """Strata 2026-07-01 loop fix: the flat mutation_verify_coverage.v1 mvc_sidecar
    schema (per-fn + chimera campaign records) has NO harness_path - it stores the
    harness as a runner COMMAND `cd <DIR> && forge test --match-path '<REL>'` plus a
    runner_cwd + source_file (the CUT). The credit loop read ONLY harness_path and
    continue'd when absent, so a genuinely non-vacuous v1 record (7/11 behaviour-
    changing mutant kills) was silently dropped -> the campaign read fail-stub-or-ghost
    next to an already-credited sibling campaign. Same serving-join class as the
    cluster-schema fix above, for the flat schema."""

    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp()).resolve()
        camp = self.ws / "chimera_harnesses" / "AprPairFeedBounds"
        camp.mkdir(parents=True)
        (camp / "AprPairFeedBounds.sol").write_text(
            "contract H{ function property_bounds() public returns(bool){ return lo<=hi; } }")
        (camp / "Sanity.t.sol").write_text(
            "contract T{ function invariant_bounds() public {} }")
        (self.ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)

    def _write(self, name, payload):
        (self.ws / ".auditooor" / "mvc_sidecar" / name).write_text(json.dumps(payload))

    def _v1_record(self, match_rel, extra=None):
        rec = {
            "schema": "auditooor.mutation_verify_coverage.v1",
            "verdict": "non-vacuous",
            "killed_count": 7, "behavior_changing_kill_count": 7,
            "source_file": str(self.ws / "src" / "AprPairFeed.sol"),
            "harness": (f"cd {self.ws / 'chimera_harnesses'} && "
                        f"/usr/bin/forge test --match-path '{match_rel}'"),
            "runner_cwd": str(self.ws),
        }
        if extra:
            rec.update(extra)
        return rec

    def test_v1_match_path_command_credits_campaign_without_harness_path(self):
        self._write("mvc-AprPairFeedBounds.json",
                    self._v1_record("AprPairFeedBounds/Sanity.t.sol"))
        proven = self.m._mutation_verified_harnesses(self.ws)
        names = {Path(p).name for p in proven}
        # the matched .t.sol AND its sibling harness .sol are both credited
        self.assertIn("Sanity.t.sol", names)
        self.assertIn("AprPairFeedBounds.sol", names)

    def test_v1_resolver_returns_none_when_file_absent(self):
        rec = self._v1_record("AprPairFeedBounds/DoesNotExist.t.sol")
        self.assertIsNone(self.m._resolve_sidecar_harness_file(rec, self.ws))

    def test_v1_vacuous_record_credits_nothing(self):
        # verdict not non-vacuous + no kills -> dropped before resolution
        rec = self._v1_record("AprPairFeedBounds/Sanity.t.sol",
                              {"verdict": "vacuous", "killed_count": 0,
                               "behavior_changing_kill_count": 0})
        self._write("mvc-vac.json", rec)
        self.assertEqual(self.m._mutation_verified_harnesses(self.ws), set())

    def test_v1_end_to_end_flips_unproven_to_proven(self):
        self._write("mvc-AprPairFeedBounds.json",
                    self._v1_record("AprPairFeedBounds/Sanity.t.sol"))
        res = self.m.evaluate(self.ws)
        self.assertEqual(res["verdict"], "pass-engine-harness-proof", res)
        self.assertEqual(res["unproven"], [], res)


if __name__ == "__main__":
    unittest.main(verbosity=2)
