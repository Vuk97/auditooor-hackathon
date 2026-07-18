#!/usr/bin/env python3
"""test_A14.py - deploy->initialize ordering-window screen (A14).

Standalone tool tools/deploy-initialize-ordering-window.py: an advisory-first,
NO-AUTO-CREDIT (verdict=needs-fuzz) trust-enforcement screen for the TEMPORAL
deploy->init window (I1: no un-guarded trust-anchor init; I2: no unvalidated
cross-proxy dependency wiring).

Non-vacuity contract exercised here:
  * PLANTED POSITIVE fires exactly once (unguarded trust-anchor initialize).
  * GUARDED NEGATIVE is silent (same init + `initializer` modifier).
  * Neutralising EITHER core predicate (init-name/modifier OR trust-anchor)
    makes the positive STOP firing -> the predicate is load-bearing.
  * The guard detector itself is load-bearing: neutralising the modifier guard
    makes the GUARDED fixture fire -> proves the guard is what silences it.
Mutation-verify against REAL fleet source is a separate, executed check (see the
returned schema); this suite proves the predicate is non-vacuous in isolation.
"""
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "deploy-initialize-ordering-window.py"


def _load():
    spec = importlib.util.spec_from_file_location("a14_mod", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["a14_mod"] = m
    spec.loader.exec_module(m)
    return m


# ---- fixtures (inline; regex tool does not compile so single strings suffice) --

# GUARDED NEGATIVE: mirrors strata StrataCDO.initialize - `initializer` modifier
# + trust-anchor establishment via an *_init parent initializer. Must be SILENT.
GUARDED = """
pragma solidity ^0.8.0;
contract StrataCDOish {
    uint256 public jrtShortfallPausePrice;
    constructor(uint256 d) {}
    function initialize(address owner_, address acm_) public virtual initializer {
        AccessControlled_init(owner_, acm_);
        jrtShortfallPausePrice = 0.01e18;
    }
    function AccessControlled_init(address o, address a) internal {}
}
"""

# PLANTED POSITIVE = GUARDED with the `initializer` modifier weakened away. Now
# an external, trust-anchor-setting initialize with NO init-guard -> front-run.
POSITIVE = GUARDED.replace("public virtual initializer", "public virtual")

# BENIGN CONFIG: an external initialize with NO trust anchor (just a numeric
# config). Un-guarded but not a security window -> silent.
BENIGN_CONFIG = """
pragma solidity ^0.8.0;
contract Cfg {
    uint256 public fee;
    function initialize(uint256 fee_) external { fee = fee_; }
}
"""

# INTERNAL HELPER: the trust-anchor setter is internal, not the reachable entry.
INTERNAL_ONLY = """
pragma solidity ^0.8.0;
contract Impl {
    address owner;
    function __init(address o) internal { owner = o; }
}
"""

# VERSIONED-INIT NEGATIVE: mirrors the Lido `Versioned` base - an external
# initialize that sets a trust anchor but is single-shot via a contract-version
# writer that reverts on re-init. A recognised general once-guard -> silent.
VERSIONED = """
pragma solidity ^0.8.0;
contract Oracleish {
    function initialize(address admin, address consensus) external {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _initializeContractVersionTo(1);
    }
    function _grantRole(bytes32 r, address a) internal {}
    function _initializeContractVersionTo(uint256 v) internal {}
    bytes32 constant DEFAULT_ADMIN_ROLE = 0x0;
}
"""

# FLAG-B POSITIVE: initializer wires a sibling dependency address from a param,
# NO non-zero validation. Guarded against front-run (has initializer) but I2 is
# still bypassable -> only the dependency flag should fire.
DEP_UNVALIDATED = """
pragma solidity ^0.8.0;
contract Wiring {
    address public strategy;
    function initialize(address strategy_) external initializer {
        strategy = strategy_;
    }
}
"""

# FLAG-B NEGATIVE: same wiring but WITH a non-zero validation -> silent.
DEP_VALIDATED = """
pragma solidity ^0.8.0;
contract Wiring2 {
    address public strategy;
    function initialize(address strategy_) external initializer {
        require(strategy_ != address(0), "zero");
        strategy = strategy_;
    }
}
"""


class TestA14(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _screen(self, src):
        return self.m.screen_source("src/x.sol", src)

    def _kinds(self, src):
        return sorted(h["flag_kind"] for h in self._screen(src))

    # ---- mutation-kill: positive fires, guarded silent -------------------
    def test_positive_fires_once(self):
        hits = [h for h in self._screen(POSITIVE)
                if h["flag_kind"] == "init-window-front-runnable"]
        self.assertEqual(len(hits), 1, "unguarded trust-anchor init must fire once")
        h = hits[0]
        self.assertEqual(h["function"], "initialize")
        self.assertEqual(h["verdict"], "needs-fuzz")
        self.assertEqual(h["init_guards_found"], [])
        self.assertEqual(h["attack_class"], "deploy-init-ordering-window")

    def test_guarded_negative_silent(self):
        self.assertNotIn("init-window-front-runnable", self._kinds(GUARDED),
                         "an `initializer`-guarded init must be silent")

    def test_benign_config_silent(self):
        # no trust anchor -> not a security window even though un-guarded.
        self.assertEqual(self._screen(BENIGN_CONFIG), [],
                         "an un-guarded numeric config setter is not a gap")

    def test_versioned_init_once_guard_silent(self):
        # the general `Versioned` single-shot base (contract-version writer) is a
        # recognised once-guard -> the trust-anchor init must be silent.
        self.assertNotIn("init-window-front-runnable", self._kinds(VERSIONED),
                         "a versioned single-shot init-once base must be silent")

    def test_internal_helper_silent(self):
        self.assertEqual(self._screen(INTERNAL_ONLY), [],
                         "an internal *_init helper is not the front-runnable entry")

    # ---- non-vacuity: BOTH halves of the fire predicate are load-bearing --
    def test_init_name_predicate_load_bearing(self):
        saved_n, saved_m = self.m._INIT_NAME_RE, self.m._INIT_MODIFIER_RE
        try:
            self.m._INIT_NAME_RE = re.compile(r"ZZZ_NEVER")
            self.m._INIT_MODIFIER_RE = re.compile(r"ZZZ_NEVER")
            self.assertEqual(self._screen(POSITIVE), [],
                             "neutralising the initializer predicate silences positive")
        finally:
            self.m._INIT_NAME_RE, self.m._INIT_MODIFIER_RE = saved_n, saved_m
        self.assertEqual(len([h for h in self._screen(POSITIVE)
                              if h["flag_kind"] == "init-window-front-runnable"]), 1)

    def test_trust_anchor_predicate_load_bearing(self):
        saved = self.m._TRUST_ANCHOR_RE
        try:
            self.m._TRUST_ANCHOR_RE = re.compile(r"ZZZ_NEVER")
            self.assertNotIn("init-window-front-runnable", self._kinds(POSITIVE),
                             "neutralising the trust-anchor predicate silences positive")
        finally:
            self.m._TRUST_ANCHOR_RE = saved

    def test_guard_detector_is_load_bearing(self):
        # If we neutralise the modifier-guard detector, the GUARDED fixture
        # becomes indistinguishable from the positive and MUST fire -> proves the
        # guard detection is exactly what silences the benign negative.
        saved = self.m._INIT_MODIFIER_RE
        try:
            # keep name-matching alive, kill only the guard-recognition role by
            # making the modifier match nothing that appears in attrs.
            self.m._INIT_MODIFIER_RE = re.compile(r"ZZZ_NEVER_MATCHES_ATTR")
            self.assertIn("init-window-front-runnable", self._kinds(GUARDED),
                          "with the guard blinded, the guarded init must fire")
        finally:
            self.m._INIT_MODIFIER_RE = saved
        self.assertNotIn("init-window-front-runnable", self._kinds(GUARDED))

    # ---- flag B: cross-init dependency validation ------------------------
    def test_dependency_unvalidated_fires(self):
        kinds = self._kinds(DEP_UNVALIDATED)
        self.assertIn("cross-init-dependency-unvalidated", kinds)
        self.assertNotIn("init-window-front-runnable", kinds,
                         "no trust anchor set -> only the dependency flag")
        h = [x for x in self._screen(DEP_UNVALIDATED)
             if x["flag_kind"] == "cross-init-dependency-unvalidated"][0]
        self.assertEqual(h["dependency_params"], ["strategy_"])
        self.assertEqual(h["verdict"], "needs-fuzz")

    def test_dependency_validated_silent(self):
        self.assertNotIn("cross-init-dependency-unvalidated",
                         self._kinds(DEP_VALIDATED),
                         "a non-zero validated dependency wiring is silent")

    # ---- advisory-first gating + NO-AUTO-CREDIT --------------------------
    def _ws(self, name, src):
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / "src" / name).write_text(src, encoding="utf-8")
        return d

    def test_advisory_off_by_default(self):
        os.environ.pop(self.m.ENV_FLAG, None)
        ws = self._ws("x.sol", POSITIVE)
        res = self.m.evaluate(ws)
        self.assertIsNone(res.get("init_ordering_window"),
                          "advisory must be OFF (None) by default")
        self.assertFalse((ws / self.m.OUT_REL).exists(),
                         "no jsonl emitted when disabled")

    def test_enabled_emits_needs_fuzz_jsonl(self):
        os.environ[self.m.ENV_FLAG] = "1"
        try:
            ws = self._ws("x.sol", POSITIVE)
            summ = self.m.evaluate(ws).get("init_ordering_window")
            self.assertIsNotNone(summ)
            self.assertTrue(summ["enabled"])
            self.assertEqual(summ["verdict"], "needs-fuzz")
            self.assertGreaterEqual(summ["count"], 1)
            jl = ws / self.m.OUT_REL
            self.assertTrue(jl.exists())
            rows = [json.loads(x) for x in jl.read_text().splitlines() if x.strip()]
            self.assertTrue(rows and all(r["verdict"] == "needs-fuzz" for r in rows),
                            "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        finally:
            os.environ.pop(self.m.ENV_FLAG, None)

    def test_analyze_fail_open_no_solidity(self):
        d = Path(tempfile.mkdtemp())
        hyps, acc = self.m.analyze(d)
        self.assertEqual(hyps, [])
        self.assertEqual(acc["status"], "no-solidity")


if __name__ == "__main__":
    unittest.main()
