#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-INVARIANT-FUZZ-GATE registered via agent-pathspec-register.py -->
"""Guard: invariant-fuzz-completeness is ASSET-CENTRIC + has a tightened
real-engine-evidence predicate.

Two capability gaps this test locks in (2026-07-02):

1. ASSET-CENTRIC coverage. The old gate only iterated the harnesses that HAPPEN
   to exist, so a workspace where most value-moving in-scope FILES have zero
   economic invariant still passed. Now the gate enumerates the value-moving
   in-scope file set (value_moving_functions.json intersected with
   inscope_units.jsonl) minus the harness CUT set actually fuzzed
   (fuzz_campaign_receipt campaigns[].cut with a >=1M run + mvc_sidecar
   source_file). A residual value-moving file with no real harness and no typed
   per-asset disposition is an asset-gap:
     - ADVISORY by default -> warn-invariant-fuzz-asset-gap (exit 0).
     - HARD-FAIL only under AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT=1 ->
       fail-invariant-fuzz-asset-gap (exit 1).
   A typed per-asset disposition over the gap file closes it (no gap).

2. TIGHTENED real-engine-evidence. A harness counts as coverage-guided-fuzzed
   ONLY when a raw fuzz log shows medusa Total calls >= 1M OR echidna >= 500K.
   Three non-cases must NOT alone satisfy actually-fuzzed:
     (a) a bare `forge test` baseline on a Sanity.t.sol (genuine_coverage False,
         no scaled counter),
     (b) a genuine_coverage:false manifest,
     (c) an echidna assertion-never-reached vacuous witness (0 calls).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ifc_asset", str(_TOOLS / "invariant-fuzz-completeness.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["ifc_asset"] = m
spec.loader.exec_module(m)

_STRICT_ENV = "AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT"


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _base_ws(value_moving_files, campaign_cuts=(), mvc_sources=()):
    """Build a workspace with the two authoritative manifests + a real fuzzed
    harness so the harness-centric bar itself always passes; the only variable
    under test here is the ASSET-coverage delta and the engine-evidence strictness.
    Returns the ws Path. `value_moving_files` are the value-moving in-scope FILES;
    `campaign_cuts`/`mvc_sources` are the CUTs that HAVE a real harness."""
    ws = Path(tempfile.mkdtemp())
    au = ws / ".auditooor"
    au.mkdir(parents=True)
    # value_moving_functions.json: one value-moving fn per file
    _write(au / "value_moving_functions.json", json.dumps({
        "functions": [
            {"file": f, "function": "move", "transfer_hit": True, "ledger_write_hit": False}
            for f in value_moving_files
        ]}))
    # inscope_units.jsonl: every value-moving file is in-scope
    _write(au / "inscope_units.jsonl", "\n".join(
        json.dumps({"file": f, "function": "move", "lang": "solidity"})
        for f in value_moving_files))
    # a genuine real harness so the harness-centric bar passes (2 props, mutation,
    # >=1M engine evidence). Its CUT is the FIRST campaign_cut if given.
    hd = ws / "chimera_harnesses" / "H"
    hd.mkdir(parents=True)
    _write(hd / "Properties.sol",
           "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract Properties {\n"
           "    function property_a() public view returns (bool) { return true; }\n"
           "    function property_b() public view returns (bool) { return true; }\n"
           "    function test_mutation_breaks_a() public { assertFalse(false); }\n}\n")
    deng = au / "deep-engine-findings"
    deng.mkdir(parents=True)
    _write(deng / "H-invariant-fuzz.md",
           "# H\n" + ("x" * 400) +
           "\n[PASS] invariant_a() (runs: 25000, calls: 1200000, reverts: 0)\n")
    # campaign receipt: each cut got a >=1M medusa run
    if campaign_cuts:
        _write(au / "fuzz_campaign_receipt.json", json.dumps({
            "schema": "auditooor.fuzz_campaign_receipt.v1",
            "campaigns": [
                {"name": Path(c).stem, "engine": "medusa", "cut": c,
                 "result": {"calls": 1_200_000, "passed": 2, "failed": 0}}
                for c in campaign_cuts]}))
    # mvc_sidecar: each source is mutation-verified
    if mvc_sources:
        sc = au / "mvc_sidecar"
        sc.mkdir(parents=True)
        for i, src in enumerate(mvc_sources):
            # a REAL harness for asset-coverage = mutation-verified AND a campaign that
            # cleared the engine call floor (fuzz-depth is decoupled from mutation-quality;
            # a bare mutation_verified sidecar no longer credits the >=1M asset gap).
            _write(sc / f"mvc-{i}.json", json.dumps({
                "schema": "auditooor.mutation_verify_coverage.v1",
                "source_file": src, "mutation_verified": True,
                "engine": "medusa", "campaign_calls": 1_200_000}))
    return ws


class TestAssetCentric(unittest.TestCase):
    def setUp(self):
        os.environ.pop(_STRICT_ENV, None)

    def tearDown(self):
        os.environ.pop(_STRICT_ENV, None)

    # ---- CASE 1: asset gap is ADVISORY by default, HARD-FAIL under strict env ----
    def test_asset_gap_advisory_by_default(self):
        # 3 value-moving files, only 1 has a real fuzzed harness -> 2 gaps.
        vm = ["src/A.sol", "src/B.sol", "src/C.sol"]
        ws = _base_ws(vm, campaign_cuts=["src/A.sol"])
        r = m.evaluate(ws)
        # advisory: verdict is a WARN, exit code 0 (never bricks a prior audit).
        self.assertEqual(r["verdict"], "warn-invariant-fuzz-asset-gap")
        self.assertTrue(r["asset_coverage"]["applicable"])
        self.assertEqual(sorted(r["asset_coverage"]["gaps"]), ["src/B.sol", "src/C.sol"])
        self.assertEqual(m.main(["--workspace", str(ws)]), 0)

    def test_asset_gap_hard_fails_under_strict_env(self):
        vm = ["src/A.sol", "src/B.sol", "src/C.sol"]
        ws = _base_ws(vm, campaign_cuts=["src/A.sol"])
        os.environ[_STRICT_ENV] = "1"
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-invariant-fuzz-asset-gap")
        self.assertEqual(m.main(["--workspace", str(ws)]), 1)

    def test_all_value_moving_files_covered_passes(self):
        # every value-moving file has a real harness (campaign or mvc) -> no gap.
        vm = ["src/A.sol", "src/B.sol"]
        ws = _base_ws(vm, campaign_cuts=["src/A.sol"], mvc_sources=["src/B.sol"])
        os.environ[_STRICT_ENV] = "1"  # even strict must pass when fully covered
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "pass-invariant-fuzz-complete")
        self.assertEqual(r["asset_coverage"]["gaps"], [])

    def test_typed_disposition_closes_the_gap(self):
        # a value-moving file with no harness but a typed per-asset disposition is
        # NOT a gap (the disposition mechanism is honored).
        vm = ["src/A.sol", "src/Config.sol"]
        ws = _base_ws(vm, campaign_cuts=["src/A.sol"])
        # Stub the NED disposition lookup so Config.sol resolves to a disposition.
        real_load = m._NED_MOD.load_dispositions if m._NED_MOD else None
        real_fid = m._NED_MOD.file_is_dispositioned if m._NED_MOD else None
        if m._NED_MOD is None:
            self.skipTest("non_economic_disposition lib not loadable")
        m._NED_MOD.load_dispositions = lambda _ws: [{"cut_path": "src/Config.sol"}]
        m._NED_MOD.file_is_dispositioned = (
            lambda f, disp: {"classification": "oos-config", "rationale": "governance-only"}
            if f == "src/Config.sol" else None)
        try:
            os.environ[_STRICT_ENV] = "1"  # even strict passes: gap is dispositioned
            r = m.evaluate(ws)
            self.assertEqual(r["verdict"], "pass-invariant-fuzz-complete")
            self.assertEqual(r["asset_coverage"]["gaps"], [])
            self.assertIn("src/Config.sol", r["asset_coverage"]["dispositioned"])
        finally:
            m._NED_MOD.load_dispositions = real_load
            m._NED_MOD.file_is_dispositioned = real_fid

    def test_no_value_moving_manifest_is_noop_all_language(self):
        # No value_moving_functions.json (e.g. a non-sol / early workspace) -> the
        # asset check is a no-op, verdict falls back to harness-centric PASS.
        ws = _base_ws([], campaign_cuts=[])
        # remove the (empty) manifest to simulate absence
        (ws / ".auditooor" / "value_moving_functions.json").unlink()
        os.environ[_STRICT_ENV] = "1"
        r = m.evaluate(ws)
        self.assertFalse(r["asset_coverage"]["applicable"])
        self.assertEqual(r["verdict"], "pass-invariant-fuzz-complete")

    # ---- CASE 2/3: tightened real-engine-evidence predicate ----
    def test_medusa_1m_log_is_actually_fuzzed(self):
        text = "medusa fuzzing\nTotal calls: 1,203,538\nelapsed time: 3600s\n"
        self.assertTrue(m._log_shows_coverage_guided_fuzz(text))

    def test_echidna_500k_log_is_actually_fuzzed(self):
        text = "echidna campaign\ncalls tested: 600000\n"
        self.assertTrue(m._log_shows_coverage_guided_fuzz(text))

    def test_bare_forge_test_baseline_is_NOT_fuzzed(self):
        # a `forge test` baseline on Sanity.t.sol: no scaled counter -> baseline-only.
        text = "Running forge test Sanity.t.sol\n[PASS] test_sanity() (gas: 21000)\n"
        self.assertFalse(m._log_shows_coverage_guided_fuzz(text))

    def test_genuine_coverage_false_is_NOT_fuzzed(self):
        # even with a big-looking counter, a genuine_coverage:false manifest is
        # baseline-only and must be rejected.
        text = 'medusa\n"genuine_coverage": false\nTotal calls: 2000000\n'
        self.assertFalse(m._log_shows_coverage_guided_fuzz(text))

    def test_echidna_vacuous_never_reached_witness_is_NOT_fuzzed(self):
        # echidna at 50116 calls but the assertion was never reached (vacuous):
        # under the echidna 500K floor -> not actually-fuzzed.
        text = ("echidna run\ncalls tested: 50116\n"
                "echidna_solvency: passing (assertion never reached)\n")
        self.assertFalse(m._log_shows_coverage_guided_fuzz(text))

    def test_500k_medusa_smoke_under_1m_floor_is_NOT_fuzzed(self):
        text = "medusa\nTotal calls: 500000\n"
        self.assertFalse(m._log_shows_coverage_guided_fuzz(text))


if __name__ == "__main__":
    unittest.main()
