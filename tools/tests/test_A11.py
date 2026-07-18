#!/usr/bin/env python3
"""test_A11.py - delegatecall-context-binding oracle (A11).

Extends tools/slither_predicates.py with `trusts_context_binding_under_delegate`
(sibling of #11 has_low_level_delegatecall): an advisory-first, NO-AUTO-CREDIT
(verdict='needs-fuzz') detector that flags a delegatecall-TARGET function which
TRUSTS the execution context (writes storage / reads address(this) or
msg.sender-for-auth) with NO onlyProxy / notDelegated / address(this)==__self /
_onlyDelegateCall guard anywhere in its closure.

Non-vacuity / mutation-kill:
  - the CLEAN synthetic fixture (guarded context-sensitive write) is silent;
  - the MUTANT (guard dropped) fires exactly once;
  - the guard-detection and delegate-target seed are each proven load-bearing.

FP-guard: intended-caller-context delegate MACHINERY (EIP-1967 Proxy dispatcher,
OZ Address.functionDelegateCall, self-delegatecall Multicall, Clones.clone
deployment) is dropped.

Natural instance (read-only): optimism OPCMv2 - benign is clean; dropping
`_onlyDelegateCall()` from upgrade() fires. Guarded via skipUnless when the ws
is not present on this host.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "slither_predicates.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "A11"
_OPCM = Path(
    "/Users/wolf/audits/optimism/src/packages/contracts-bedrock/src/L1/opcm/"
    "OPContractsManagerV2.sol"
)


def _load():
    spec = importlib.util.spec_from_file_location("sp_a11", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sp_a11"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestDelegateContextBinding(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _hits(self, name, covered=None):
        return self.m.trusts_context_binding_under_delegate(
            (_FIX / name).read_text(), covered=covered)

    # ---- mutation-kill (synthetic) --------------------------------------
    def test_mutant_fires(self):
        hits = self._hits("mutant.sol")
        self.assertEqual(len(hits), 1, "mutant (guard dropped) must fire once")
        h = hits[0]
        self.assertEqual(h["contract"], "LogicModule")
        self.assertEqual(h["function"], "setConfig")
        self.assertEqual(h["trust_signal"], "storage-write")
        self.assertEqual(h["canonical_class"], "delegatecall-context-binding")

    def test_clean_silent(self):
        self.assertEqual(self._hits("clean.sol"), [],
                         "guarded context-sensitive write must be silent")

    # ---- NO-AUTO-CREDIT verdict contract --------------------------------
    def test_verdict_is_needs_fuzz_no_auto_credit(self):
        for h in self._hits("mutant.sol"):
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertFalse(h["auto_credit"])

    # ---- load-bearing: guard detection ----------------------------------
    def test_guard_detection_is_load_bearing(self):
        # Neutralise all three guard signals -> the CLEAN fixture must now FIRE,
        # proving the guard is what suppresses it (not a vacuous always-empty).
        saved = (self.m._A11_GUARD_MODIFIER_RE, self.m._A11_GUARD_HELPER_RE,
                 self.m._A11_SELF_CMP_RE)
        never = re.compile(r"ZZZ_NEVER_MATCHES")
        try:
            self.m._A11_GUARD_MODIFIER_RE = never
            self.m._A11_GUARD_HELPER_RE = never
            self.m._A11_SELF_CMP_RE = never
            hits = self._hits("clean.sol")
            self.assertEqual(len(hits), 1,
                             "neutralising the guard must expose the clean write")
            self.assertEqual(hits[0]["function"], "setConfig")
        finally:
            (self.m._A11_GUARD_MODIFIER_RE, self.m._A11_GUARD_HELPER_RE,
             self.m._A11_SELF_CMP_RE) = saved
        self.assertEqual(self._hits("clean.sol"), [], "restored guard re-silences")

    # ---- load-bearing: delegate-target seed -----------------------------
    def test_delegate_target_seed_is_load_bearing(self):
        saved = self.m._A11_DELEGATE_TARGET_TOKEN_RE
        try:
            self.m._A11_DELEGATE_TARGET_TOKEN_RE = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(self._hits("mutant.sol"), [],
                             "no delegate-target seed -> no A11 hypothesis")
        finally:
            self.m._A11_DELEGATE_TARGET_TOKEN_RE = saved
        self.assertEqual(len(self._hits("mutant.sol")), 1)

    # ---- FP-guard -------------------------------------------------------
    def test_fp_proxy_dispatcher_silent(self):
        self.assertEqual(self._hits("fp_proxy.sol"), [],
                         "EIP-1967 proxy dispatcher is not a trusting target")

    def test_fp_multicall_clone_address_silent(self):
        self.assertEqual(self._hits("fp_multicall_clone_address.sol"), [],
                         "delegate machinery (multicall/clone/Address) is silent")

    def test_view_function_not_flagged(self):
        # a view that reads address(this) in a delegate-target contract is not a
        # storage-corruption risk -> silent.
        src = ("pragma solidity ^0.8.0;\ncontract M {\n"
               "  address __self;\n"
               "  function _g() internal { require(address(this) != __self); }\n"
               "  function peek() external view returns (address) { return address(this); }\n"
               "}\n")
        self.assertEqual(
            self.m.trusts_context_binding_under_delegate(src), [],
            "a view cannot corrupt storage under mis-context")

    # ---- DEDUP boundary (A1): consume covered_by, never re-derive --------
    def test_dedup_covered_by_consumed_verbatim(self):
        # with no covered set -> distinct (covered_by False)
        h0 = self._hits("mutant.sol")
        self.assertFalse(h0[0]["covered_by"])
        # a covering set keyed on (contract,function) -> tagged covered
        h1 = self._hits("mutant.sol", covered={("LogicModule", "setConfig")})
        self.assertTrue(h1[0]["covered_by"])
        # a covering set keyed on the bare function name also works
        h2 = self._hits("mutant.sol", covered={"setConfig"})
        self.assertTrue(h2[0]["covered_by"])
        # a callable predicate is honoured
        h3 = self._hits("mutant.sol", covered=lambda k: k[1] == "setConfig")
        self.assertTrue(h3[0]["covered_by"])

    # ---- advisory-first gate (OFF by default) ---------------------------
    def test_advisory_off_by_default(self):
        os.environ.pop(self.m._A11_ENV, None)
        self.assertFalse(self.m._a11_advisory_enabled())

    def test_advisory_on_when_env_set(self):
        os.environ[self.m._A11_ENV] = "1"
        try:
            self.assertTrue(self.m._a11_advisory_enabled())
        finally:
            os.environ.pop(self.m._A11_ENV, None)

    # ---- file-scan convenience ------------------------------------------
    def test_directory_scan(self):
        rows = self.m.delegate_context_binding_hypotheses(_FIX)
        fns = {(r["contract"], r["function"]) for r in rows}
        self.assertIn(("LogicModule", "setConfig"), fns)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in rows))

    # ---- natural instance (read-only) -----------------------------------
    @unittest.skipUnless(_OPCM.is_file(), "optimism ws not present on this host")
    def test_natural_instance_opcm(self):
        src = _OPCM.read_text()
        # BENIGN copy (never mutate the shared ws in place).
        d = Path(tempfile.mkdtemp())
        (d / "benign.sol").write_text(src)
        self.assertEqual(
            self.m.trusts_context_binding_under_delegate(src), [],
            "OPCMv2 as-is (every upgrade path guarded) must be clean")
        # MUTANT: drop _onlyDelegateCall() from upgrade() only.
        mut = src.replace(
            "function upgrade(UpgradeInput memory _inp) external returns "
            "(ChainContracts memory) {\n        _onlyDelegateCall();",
            "function upgrade(UpgradeInput memory _inp) external returns "
            "(ChainContracts memory) {", 1)
        self.assertNotEqual(mut, src, "mutation must apply")
        (d / "mutant.sol").write_text(mut)
        hits = self.m.trusts_context_binding_under_delegate(mut)
        self.assertTrue(any(h["function"] == "upgrade" for h in hits),
                        "dropping _onlyDelegateCall() from upgrade() must fire")
        for h in hits:
            self.assertEqual(h["verdict"], "needs-fuzz")


if __name__ == "__main__":
    unittest.main()
