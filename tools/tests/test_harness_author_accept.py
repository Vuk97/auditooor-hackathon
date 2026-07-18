#!/usr/bin/env python3
"""Guard: tools/harness-author-accept.py - the author-time acceptance gate (item E).

The gate is a THIN COMPOSITION of five already-landed enforcement checks. These
tests are genuine fail-before / pass-after guards:

  - a sentinel / dead-CUT harness FAILS, and the FAIL list NAMES the deep-vacuity
    modes (dead-CUT-guard) and the mutation-oracle non-credit reason
    (no-behavior-changing-kill). Each assertion would FAIL if the wrapper were a
    no-op.
  - a genuine morpho VaultV2-style harness (real CUT bound in setUp, a witness
    counter, a finite cap invariant) with an in-scope manifest AND a conforming
    mvc_sidecar fixture whose harness_source_sha256 matches -> pass-harness-accept.
    The mutation oracle is STUBBED with an injected non-vacuous verdict (the spec
    explicitly permits stubbing the oracle call with a fixture sidecar) so the
    test does not need a live forge/medusa toolchain.
  - an ssv-style sentinel harness with a stale/panic-only sidecar FAILS, listing
    sentinel-body and equivalent-mutant-only.

Python 3.14: each importlib.exec_module is preceded by sys.modules[name]=mod so a
re-entrant import sees the partially-initialised module.
"""
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # py3.14: set BEFORE exec_module
    spec.loader.exec_module(mod)
    return mod


HAA = _load(_TOOLS / "harness-author-accept.py", "harness_author_accept_t")


# ---------------------------------------------------------------------------
# Workspace / fixture builders.
# ---------------------------------------------------------------------------
def _ws() -> Path:
    return Path(tempfile.mkdtemp())


def _write_inscope(ws: Path, files: list[str]) -> None:
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "inscope_units.jsonl").open("w", encoding="utf-8") as fh:
        for f in files:
            fh.write(json.dumps({"file": f, "lang": "solidity"}) + "\n")


# The schema string the invariant-fuzz-completeness mvc_sidecar reader requires.
_MVC_SCHEMA = "auditooor.mutation_verify_coverage.v1"


def _write_sidecar(ws: Path, harness_path: Path, *, invariants, hash_ok=True,
                   verdict="non-vacuous", behavior_changing=1) -> None:
    d = ws / ".auditooor" / "mvc_sidecar"
    d.mkdir(parents=True, exist_ok=True)
    htext = harness_path.read_text(encoding="utf-8") if harness_path.is_file() else ""
    real_hash = hashlib.sha256(htext.encode("utf-8")).hexdigest()
    inv0 = invariants[0] if invariants else "invariant_cap"
    rec = {
        "schema": _MVC_SCHEMA,
        "harness_path": str(harness_path.resolve()),
        "verdict": verdict,
        "mutation_verified": True,
        "invariants": invariants,
        "behavior_changing_kill_count": behavior_changing,
        "harness_source_sha256": real_hash if hash_ok else ("0" * 64),
        # a passing+executed baseline so the fuzz-completeness reader credits the
        # run, and a GENUINE invariant-assertion kill tail (not a setUp()/panic).
        "baseline": {"status": "pass",
                     "output_tail": "[PASS] invariant_cap() (runs: 25000, calls: 1024000)"},
        "mutant_results": [{
            "killed": True,
            "kill_kind": "behavior-changing",
            "output_tail": f"{inv0}() FAIL (behavior-changing guard-removal mutant)",
        }],
    }
    (d / "mvc-fixture.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")


# A genuine morpho VaultV2-style harness: real CUT deployed + bound in setUp, a
# reachability witness asserted >0, a finite-cap invariant reading the real CUT.
GENUINE_HARNESS = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;
import {VaultV2} from "src/VaultV2.sol";

contract VaultV2InvariantHandler {
    VaultV2 internal vault;
    uint256 internal wDeposit;            // reachability witness

    function setUp() public {
        vault = new VaultV2();            // REAL CUT deployed + bound
    }

    function h_deposit(uint256 seed) external {
        uint256 amt = bound(seed, 1, token.balanceOf(address(this)));
        try vault.deposit(amt, address(this)) { wDeposit++; } catch {}
    }

    // >=5 distinct fuzz actions so a multi-step exploit can be composed.
    function h_withdraw(uint256 seed) external { vault.withdraw(seed); }
    function h_redeem(uint256 seed) external { vault.redeem(seed); }
    function h_allocate(uint256 seed) external { vault.allocate(seed); }
    function h_deallocate(uint256 seed) external { vault.deallocate(seed); }

    function invariant_reachability() public {
        assertGt(wDeposit, 0);            // witness > 0
    }

    function invariant_cap() public {
        assertLe(vault.allocation(), vault.absoluteCap());  // REAL getter read
    }
}
"""

# Dead-CUT-guard sentinel harness: bindTarget defined but setUp never calls it,
# so target stays address(0); every real call is behind if(address(t)!=0).
DEAD_CUT_HARNESS = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

contract SiloFacet_Invariant {
    address internal target;

    function bindTarget(address t) public { target = t; }

    function setUp() public {
        // NEVER calls bindTarget -> target stays address(0)
    }

    function invariant_x() public {
        if (address(target) != address(0)) {
            assertEq(uint256(1), uint256(1));
        }
    }
}
"""

# ssv-style pure sentinel: assert(true).
SENTINEL_HARNESS = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

contract Halmos_SSVClusters_deposit {
    function check_deposit_does_not_break_core_invariant() public {
        assert(true);
    }
}
"""


class GenuineHarnessPasses(unittest.TestCase):
    """A genuine VaultV2-style harness + in-scope + conforming sidecar +
    stubbed non-vacuous oracle -> pass-harness-accept."""

    def setUp(self):
        self.ws = _ws()
        # the harness lives in the recon dir alongside its props + a mutation
        # test so it is the SINGLE harness dir invariant-fuzz-completeness scans
        # (mirrors morpho chimera_harnesses/VaultV2/test/recon layout).
        hd = self.ws / "chimera_harnesses" / "VaultV2" / "test" / "recon"
        hd.mkdir(parents=True, exist_ok=True)
        self.hp = hd / "VaultV2InvariantHandler.sol"
        self.hp.write_text(GENUINE_HARNESS, encoding="utf-8")
        _write_inscope(self.ws, ["src/VaultV2.sol"])
        # genuine engine evidence so invariant-fuzz-completeness passes (>=1M).
        self._fuzz_evidence(hd)
        self.invariants = ["invariant_reachability", "invariant_cap"]
        _write_sidecar(self.ws, self.hp, invariants=self.invariants)
        # stubbed oracle verdict: non-vacuous, behavior-changing, witness reached,
        # every invariant attributed (the spec permits stubbing the oracle call).
        self.oracle = {
            "verdict": "non-vacuous",
            "behavior_changing_kill_count": 2,
            "witness_reached": True,
            "invariants": self.invariants,
            "invariant_mutant_attribution": {
                "invariant_reachability": ["m1"],
                "invariant_cap": ["m2"],
            },
            "reason": "harness FAILED on 2/2 mutants with a behavior-changing kill",
        }

    def _fuzz_evidence(self, hd: Path):
        # invariant-fuzz-completeness scans harness DIRS for props + a mutation
        # test + engine evidence. Add an in-tree mutation test alongside the
        # genuine harness, plus a >=1M engine artifact.
        (hd / "Properties.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\n"
            "contract Properties {\n"
            "    function property_cap() public view returns (bool) { return true; }\n"
            "    function property_reach() public view returns (bool) { return true; }\n"
            "    function test_mutation_breaks_cap() public { assertFalse(false); }\n}\n",
            encoding="utf-8")
        deng = self.ws / ".auditooor" / "deep-engine-findings"
        deng.mkdir(parents=True, exist_ok=True)
        (deng / "VaultV2-fuzz.md").write_text(
            "# VaultV2 invariant fuzz\n" + ("x" * 400) +
            "\n[PASS] invariant_cap() (runs: 25000, calls: 1024000, reverts: 3)\n",
            encoding="utf-8")

    def test_pass(self):
        res = HAA.accept(harness=self.hp, ws=self.ws, oracle_verdict=self.oracle)
        self.assertEqual(res["verdict"], "pass-harness-accept",
                         msg=f"unexpected fails: {res['fails']}")
        self.assertEqual(res["fails"], [])
        self.assertEqual(HAA._render(res), "pass-harness-accept")

    def test_static_check_passes_on_genuine(self):
        # The genuine harness must NOT trip any deep-vacuity mode.
        self.assertEqual(HAA._check_static_vacuity(GENUINE_HARNESS), [])

    def test_inscope_check_passes(self):
        self.assertEqual(HAA._check_inscope(self.ws, self.hp), [])

    def test_sidecar_check_passes(self):
        self.assertEqual(HAA._check_sidecar(self.ws, self.hp), [])


class DeadCutHarnessFails(unittest.TestCase):
    """A dead-CUT-guard harness FAILS, listing dead-CUT-guard +
    no-behavior-changing-kill (the oracle's non-credit class)."""

    def setUp(self):
        self.ws = _ws()
        self.hp = self.ws / "test" / "SiloFacet_Invariant.sol"
        self.hp.parent.mkdir(parents=True, exist_ok=True)
        self.hp.write_text(DEAD_CUT_HARNESS, encoding="utf-8")
        _write_inscope(self.ws, ["src/SiloFacet.sol"])
        # oracle reports vacuous (no behavior-changing kill): a dead-CUT harness
        # asserts only ghost state, so all mutants survive.
        self.oracle = {
            "verdict": "vacuous",
            "behavior_changing_kill_count": 0,
            "reason": "harness PASSED on ALL mutants; it checks nothing real",
        }

    def test_fails_listing_modes(self):
        res = HAA.accept(harness=self.hp, ws=self.ws, oracle_verdict=self.oracle)
        self.assertEqual(res["verdict"], "fail-harness-accept")
        joined = "\n".join(res["fails"])
        self.assertIn("dead-CUT-guard", joined)
        self.assertIn("no-behavior-changing-kill", joined)

    def test_render_lists_fails(self):
        res = HAA.accept(harness=self.hp, ws=self.ws, oracle_verdict=self.oracle)
        rendered = HAA._render(res)
        self.assertTrue(rendered.startswith("FAIL harness-author-accept"))
        self.assertIn("dead-CUT-guard", rendered)

    def test_static_detector_fires(self):
        fails = HAA._check_static_vacuity(DEAD_CUT_HARNESS)
        self.assertTrue(any(f.startswith("dead-CUT-guard") for f in fails))


class SentinelStalePanicFails(unittest.TestCase):
    """An ssv-style assert(true) sentinel with a stale/panic-only sidecar FAILS,
    listing sentinel-body and equivalent-mutant-only."""

    def setUp(self):
        self.ws = _ws()
        self.hp = self.ws / "test" / "Halmos_SSVClusters_deposit.sol"
        self.hp.parent.mkdir(parents=True, exist_ok=True)
        self.hp.write_text(SENTINEL_HARNESS, encoding="utf-8")
        _write_inscope(self.ws, ["src/SSVClusters.sol"])
        # panic-only / equivalent-mutant-only oracle verdict (not credited).
        self.oracle = {
            "verdict": "equivalent-mutant-only",
            "behavior_changing_kill_count": 0,
            "reason": "1 panic-only EVM-enforced kill, ZERO non-panic "
                      "behavior-changing kills - NOT credited",
        }

    def test_fails_listing_sentinel_and_equivalent_mutant(self):
        res = HAA.accept(harness=self.hp, ws=self.ws, oracle_verdict=self.oracle)
        self.assertEqual(res["verdict"], "fail-harness-accept")
        joined = "\n".join(res["fails"])
        self.assertIn("sentinel-body", joined)
        self.assertIn("equivalent-mutant-only", joined)

    def test_stale_sidecar_detected(self):
        # bank a sidecar whose recorded hash does NOT match the on-disk harness.
        _write_sidecar(self.ws, self.hp, invariants=[], hash_ok=False)
        fails = HAA._check_sidecar(self.ws, self.hp)
        self.assertTrue(any("stale-sidecar" in f for f in fails))


class CompositionAndErrorPaths(unittest.TestCase):
    """The wrapper is pure composition: missing manifest/sidecar are typed FAILs,
    a missing harness file is a typed error, and partial-attribution is surfaced."""

    def test_missing_harness_is_error(self):
        ws = _ws()
        res = HAA.accept(harness=ws / "nope.sol", ws=ws, oracle_verdict={})
        self.assertEqual(res["verdict"], "error")
        self.assertTrue(HAA._render(res).startswith("error:"))

    def test_missing_inscope_manifest_fails(self):
        ws = _ws()
        hp = ws / "H.sol"
        hp.write_text(GENUINE_HARNESS, encoding="utf-8")
        fails = HAA._check_inscope(ws, hp)
        self.assertTrue(any("inscope-missing" in f for f in fails))

    def test_missing_sidecar_dir_fails(self):
        ws = _ws()
        hp = ws / "H.sol"
        hp.write_text(GENUINE_HARNESS, encoding="utf-8")
        fails = HAA._check_sidecar(ws, hp)
        self.assertTrue(any("sidecar-unregistered" in f for f in fails))

    def test_partial_invariant_attribution_fails(self):
        # non-vacuous + behavior-changing, but one invariant has no attributed
        # mutant -> cluster-partially-verified (mode 16), surfaced by the wrapper.
        verdict = {
            "verdict": "non-vacuous",
            "behavior_changing_kill_count": 1,
            "witness_reached": True,
            "invariants": ["invariant_a", "invariant_b"],
            "invariant_mutant_attribution": {"invariant_a": ["m1"]},
        }
        fails = HAA._oracle_fails_from_verdict(verdict)
        self.assertTrue(any("cluster-partially-verified" in f for f in fails))
        self.assertTrue(any("invariant_b" in f for f in fails))

    def test_witness_false_fails(self):
        verdict = {
            "verdict": "non-vacuous",
            "behavior_changing_kill_count": 1,
            "witness_reached": False,
            "invariants": ["invariant_a"],
            "invariant_mutant_attribution": {"invariant_a": ["m1"]},
        }
        fails = HAA._oracle_fails_from_verdict(verdict)
        self.assertTrue(any("value-path-never-executed" in f for f in fails))


# ---------------------------------------------------------------------------
# medusa/Chimera auto-mutation-verify fallback (P1-a serving-join fix).
#
# The live oracle call in accept() first tries `function=harness.stem` (the
# forge StdInvariant convention); a medusa/Chimera property harness never has
# a function named after its own file stem, so that lookup FAILs and the gate
# must retry against the first declared property_/invariant_/h_ function
# BEFORE falling back to a manually-registered mvc_sidecar. These tests stub
# the mvc module (`HAA._mvc`) so no live forge/medusa toolchain is required,
# and assert on the checks["mutation_oracle"] verdict the retry produces.
# ---------------------------------------------------------------------------
MEDUSA_HARNESS = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;
import {FlowLimit} from "src/FlowLimit.sol";

contract FlowLimitNetFlowProperties {
    FlowLimit internal flow;
    uint256 internal wFlowed;             // reachability witness

    function setUp() public {
        flow = new FlowLimit();           // REAL CUT deployed + bound
    }

    function h_addFlowIn(uint256 seed) external {
        flow.addFlowIn(seed);
        wFlowed++;
    }

    function h_addFlowOut(uint256 seed) external { flow.addFlowOut(seed); }

    function property_net_flow_bounded() public {
        assertLe(flow.netFlow(), flow.maxFlow());  // REAL getter read
    }

    function invariant_reachability() public {
        assertGt(wFlowed, 0);
    }
}
"""

# A vacuous medusa-style harness: same naming shape (property_/invariant_/h_),
# but the property/invariant bodies are sentinel-only (assert(true)) and never
# read the CUT - a behavior-changing mutant of FlowLimit can never be killed.
MEDUSA_VACUOUS_HARNESS = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;
import {FlowLimit} from "src/FlowLimit.sol";

contract FlowLimitNetFlowVacuousProperties {
    FlowLimit internal flow;

    function setUp() public {
        flow = new FlowLimit();
    }

    function h_addFlowIn(uint256 seed) external { flow.addFlowIn(seed); }

    function property_net_flow_bounded() public {
        assert(true);                     // never reads the CUT - vacuous
    }

    function invariant_reachability() public {
        assert(true);
    }
}
"""

_MEDUSA_JSON = """{
  "fuzzing": {"workers": 4, "testLimit": 1000000, "shrinkLimit": 5000},
  "testing": {"stopOnFailedTest": false}
}
"""


class _StubMVC:
    """Stand-in for the loaded mutation-verify-coverage module: verify() looks
    only at the `function` kwarg it is called with, mirroring the real oracle's
    `LookupError -> verdict=error "function not found"` behaviour on a stem
    miss and a genuine `non-vacuous` credit on the real property name."""

    def __init__(self, killable_functions: set[str]):
        self.killable_functions = killable_functions
        self.calls: list[str] = []

    def verify(self, *, workspace, source_file, function, harness):
        self.calls.append(function)
        if function not in self.killable_functions:
            return {"schema": _MVC_SCHEMA, "verdict": "error",
                    "reason": f"function not found: {function}"}
        return {
            "verdict": "non-vacuous",
            "behavior_changing_kill_count": 1,
            "witness_reached": True,
            "invariants": [],
            "invariant_mutant_attribution": {},
            "reason": f"harness FAILED on a behavior-changing mutant of {function}",
        }


class MedusaCandidateFunctionDetection(unittest.TestCase):
    """Unit coverage for the two new detection helpers themselves."""

    def test_finds_first_property_function(self):
        self.assertEqual(
            HAA._medusa_candidate_function(MEDUSA_HARNESS),
            "h_addFlowIn")

    def test_no_candidate_when_absent(self):
        self.assertIsNone(HAA._medusa_candidate_function(
            "contract C { function foo() public {} }"))

    def test_medusa_config_detected_with_test_limit(self):
        ws = _ws()
        (ws / "medusa.json").write_text(_MEDUSA_JSON, encoding="utf-8")
        hp = ws / "test" / "H.sol"
        hp.parent.mkdir(parents=True, exist_ok=True)
        hp.write_text(MEDUSA_HARNESS, encoding="utf-8")
        self.assertTrue(HAA._has_medusa_config(ws, hp))

    def test_medusa_config_absent_without_testlimit_key(self):
        ws = _ws()
        (ws / "medusa.json").write_text('{"fuzzing": {}}', encoding="utf-8")
        hp = ws / "test" / "H.sol"
        hp.parent.mkdir(parents=True, exist_ok=True)
        hp.write_text(MEDUSA_HARNESS, encoding="utf-8")
        self.assertFalse(HAA._has_medusa_config(ws, hp))

    def test_medusa_config_absent_with_no_file(self):
        ws = _ws()
        hp = ws / "test" / "H.sol"
        hp.parent.mkdir(parents=True, exist_ok=True)
        hp.write_text(MEDUSA_HARNESS, encoding="utf-8")
        self.assertFalse(HAA._has_medusa_config(ws, hp))


class MedusaLiveOracleAutoCredit(unittest.TestCase):
    """End-to-end (through accept(), oracle_verdict=None) proof that a genuine
    medusa-style harness auto-credits via the property-function retry, and a
    vacuous medusa-style harness (same naming shape) does NOT."""

    def _build_ws(self, harness_text: str) -> tuple[Path, Path]:
        ws = _ws()
        (ws / "medusa.json").write_text(_MEDUSA_JSON, encoding="utf-8")
        hd = ws / "test" / "recon"
        hd.mkdir(parents=True, exist_ok=True)
        hp = hd / "FlowLimitNetFlowProperties.sol"
        hp.write_text(harness_text, encoding="utf-8")
        return ws, hp

    def test_genuine_medusa_harness_credits_via_property_retry(self):
        ws, hp = self._build_ws(MEDUSA_HARNESS)
        stub = _StubMVC(killable_functions={"h_addFlowIn"})
        orig_mvc = HAA._mvc
        HAA._mvc = lambda: stub
        try:
            res = HAA.accept(harness=hp, ws=ws, oracle_verdict=None, run_oracle=True)
        finally:
            HAA._mvc = orig_mvc
        # the stem lookup (file stem) must have been tried FIRST and missed,
        # then the property-function retry must have been tried and hit.
        self.assertEqual(stub.calls[0], hp.stem)
        self.assertIn("h_addFlowIn", stub.calls)
        self.assertEqual(res["checks"]["mutation_oracle"]["verdict"], "non-vacuous")
        self.assertEqual(res["checks"]["mutation_oracle"]["fails"], [])

    def test_vacuous_medusa_harness_not_credited(self):
        ws, hp = self._build_ws(MEDUSA_VACUOUS_HARNESS)
        # the vacuous fixture's h_/property_/invariant_ names never appear in
        # the stub's killable set, mirroring a real oracle that finds 0
        # behavior-changing kills for a sentinel-only property.
        stub = _StubMVC(killable_functions=set())
        orig_mvc = HAA._mvc
        HAA._mvc = lambda: stub
        try:
            res = HAA.accept(harness=hp, ws=ws, oracle_verdict=None, run_oracle=True)
        finally:
            HAA._mvc = orig_mvc
        self.assertNotEqual(res["checks"]["mutation_oracle"]["verdict"], "non-vacuous")
        self.assertTrue(res["checks"]["mutation_oracle"]["fails"])
        self.assertEqual(res["verdict"], "fail-harness-accept")

    def test_no_retry_without_medusa_config(self):
        # same property-shaped harness, but NO medusa.json/testLimit anywhere
        # up the tree -> the fallback must not fire (forge-only harnesses must
        # not be silently re-targeted at an arbitrary function).
        ws = _ws()
        hd = ws / "test" / "recon"
        hd.mkdir(parents=True, exist_ok=True)
        hp = hd / "FlowLimitNetFlowProperties.sol"
        hp.write_text(MEDUSA_HARNESS, encoding="utf-8")
        stub = _StubMVC(killable_functions={"h_addFlowIn"})
        orig_mvc = HAA._mvc
        HAA._mvc = lambda: stub
        try:
            HAA.accept(harness=hp, ws=ws, oracle_verdict=None, run_oracle=True)
        finally:
            HAA._mvc = orig_mvc
        self.assertEqual(stub.calls, [hp.stem])  # only the stem attempt, no retry


if __name__ == "__main__":
    unittest.main()
