#!/usr/bin/env python3
"""R3 enforcement-DELEGATION trust-closure screen - regression + mutation (non-vacuity).

Pins tools/arch-delegation-trust-closure.py. The tool is a GENERAL trust-enforcement
INVARIANT screen (impact-agnostic): "every relied-upon safety property (authority /
conservation / freshness) is anchored by a CONCRETE enforcement gate somewhere in its
transitive delegation closure." It is pure-source (no compiler) so this suite never
skips.

Matrix (the target property MISSING fires; PRESENT/benign is SILENT):
  - authority mutator whose closure has NO enforcement gate      -> 1 unenforced-root.
  - SAME mutator with an `onlyOwner` modifier                    -> 0 (anchored).
  - SAME mutator anchored only by a zero-address sanitisation    -> 1 (sanitisation is
        NOT an enforcement gate).
  - privileged value-mover (sweep) with no guard                 -> 1 unenforced-root.
  - a self-service deposit (msg.sender's own funds, no guard)    -> 0 (self-authorizing).
  - a construction/factory fn granting a role on a fresh proxy   -> 0 (setup context).
  - two mutually-recursive un-guarded fns, eligible root         -> 1 delegation-cycle.
  - swappable-sole-anchor (env-gated) on `msg.sender==setVar`    -> 1 (only when env set).

Non-vacuity (each core predicate is load-bearing - a mutation flips the verdict):
  - neutralise _has_enforcement_guard -> True  => the planted positive collapses 1 -> 0.
  - neutralise _sink_class -> None             => the planted positive collapses 1 -> 0.
  - neutralise _is_self_authorizing -> False   => the self-service case fires 0 -> 1.

Optional fleet-FP assertion: if the real reserve-governor / URD source is present,
assert R3 stays SILENT (0 rows) yet NON-VACUOUS (>=1 eligible root examined).
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"

RESERVE_GOV = pathlib.Path(
    "/Users/wolf/audits/reserve-governor/external/reserve-governor/contracts")
URD = pathlib.Path(
    "/Users/wolf/audits/morpho/src/universal-rewards-distributor/src")


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "arch_delegation_trust_closure", TOOLS / "arch-delegation-trust-closure.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R3 = _load_tool()


# --- synthetic fixtures ------------------------------------------------------

# authority mutator, NO enforcement gate anywhere in closure -> unenforced-root.
UNENFORCED_AUTH = """
pragma solidity ^0.8.0;
contract Roles {
    mapping(address => bool) public isAdmin;
    function grantAdmin(address a) external {
        _grantRole(a);
    }
    function _grantRole(address a) internal {
        isAdmin[a] = true;
    }
}
"""

# SAME mutator, anchored by onlyOwner modifier -> silent.
GUARDED_AUTH = """
pragma solidity ^0.8.0;
contract Roles {
    address owner;
    mapping(address => bool) public isAdmin;
    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
    function grantAdmin(address a) external onlyOwner {
        _grantRole(a);
    }
    function _grantRole(address a) internal {
        isAdmin[a] = true;
    }
}
"""

# SAME mutator, ONLY a zero-address sanitisation -> still fires (sanitisation is not
# an enforcement gate).
SANITISATION_ONLY = """
pragma solidity ^0.8.0;
contract Roles {
    mapping(address => bool) public isAdmin;
    function grantAdmin(address a) external {
        require(a != address(0), "zero");
        _grantRole(a);
    }
    function _grantRole(address a) internal {
        isAdmin[a] = true;
    }
}
"""

# privileged value-mover, no guard -> unenforced-root (conservation).
PRIV_MOVER_UNGUARDED = """
pragma solidity ^0.8.0;
interface IERC20 { function transfer(address,uint256) external; }
contract Vault {
    IERC20 token;
    function sweep(address to, uint256 amt) external {
        token.transfer(to, amt);
    }
}
"""

# self-service deposit: caller's own funds, no guard -> silent (self-authorizing).
SELF_SERVICE = """
pragma solidity ^0.8.0;
interface IERC20 { function transferFrom(address,address,uint256) external; }
contract Vault {
    IERC20 token;
    mapping(address => uint256) public balances;
    function deposit(uint256 amt) external {
        token.transferFrom(msg.sender, address(this), amt);
        balances[msg.sender] += amt;
    }
}
"""

# construction/factory fn granting a role on a fresh proxy -> silent (setup context).
FACTORY_SETUP = """
pragma solidity ^0.8.0;
contract Factory {
    function deployVault(address admin) external returns (address v) {
        v = address(new Vault());
        Vault(v).grantRole(admin);
    }
}
contract Vault { function grantRole(address a) external {} }
"""

# delegation cycle: two un-guarded fns call each other; eligible root -> cycle.
# The authority sink is a plain state-var write (`admin = a`) so the closure is
# severity-eligible; the mutual `_stepOne`<->`_stepTwo` recursion forms the cycle.
DELEGATION_CYCLE = """
pragma solidity ^0.8.0;
contract Roles {
    address admin;
    function grantAdmin(address a) external {
        _stepOne(a);
    }
    function _stepOne(address a) internal {
        _stepTwo(a);
    }
    function _stepTwo(address a) internal {
        if (a != address(0)) { _stepOne(a); }
        admin = a;
    }
}
"""

# OZ public role mutator wrapper: `grantRole(...)` self-enforces onlyRole(admin) in
# the OZ base (out-of-scan-scope lib) -> the wrapper is anchored -> SILENT.
GRANTROLE_PUBLIC_WRAPPER = """
pragma solidity ^0.8.0;
contract ACL {
    function grantCall(bytes32 role, address who) public {
        grantRole(role, who);
    }
    function grantRole(bytes32 role, address who) public virtual {}
}
"""

# Internal `_grantRole(...)` is UNGUARDED in OZ; reaching it with no other gate is
# the true-positive unenforced-root shape -> FIRES.
GRANTROLE_INTERNAL_WRAPPER = """
pragma solidity ^0.8.0;
contract ACL {
    mapping(bytes32 => mapping(address => bool)) roles;
    function grantCall(bytes32 role, address who) public {
        _grantRole(role, who);
    }
    function _grantRole(bytes32 role, address who) internal {
        roles[role][who] = true;
    }
}
"""

# swappable sole-anchor: the ONLY gate keys on a settable address var. The
# authority sink is a plain state-var write (`admin = a`) so the root is eligible;
# the sole `require(msg.sender == controller)` anchor keys on `controller`, which
# `setController` can reassign (attacker-swappable node).
SWAPPABLE_ANCHOR = """
pragma solidity ^0.8.0;
contract Roles {
    address controller;
    address admin;
    function setController(address c) external { controller = c; }
    function grantAdmin(address a) external {
        require(msg.sender == controller, "no");
        admin = a;
    }
}
"""


def _run(src: str, env: dict | None = None):
    with tempfile.TemporaryDirectory() as d:
        ws = pathlib.Path(d)
        f = ws / "C.sol"
        f.write_text(src, encoding="utf-8")
        old = {}
        if env:
            for k, v in env.items():
                old[k] = os.environ.get(k)
                os.environ[k] = v
        try:
            acct = R3.screen(ws, f)
        finally:
            for k, v in (old or {}).items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        rows = []
        jl = ws / ".auditooor" / R3.OUT_JSONL
        if jl.is_file():
            rows = [json.loads(x) for x in jl.read_text().splitlines() if x.strip()]
        return acct, rows


class TestR3Matrix(unittest.TestCase):
    def test_unenforced_authority_fires(self):
        acct, rows = _run(UNENFORCED_AUTH)
        self.assertEqual(acct["status"], "ok")
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["violation"], "unenforced-root")
        self.assertEqual(rows[0]["property_class"], "authority")
        self.assertEqual(rows[0]["verdict"], "needs-fuzz")
        self.assertTrue(rows[0]["advisory"])

    def test_guarded_authority_silent(self):
        acct, rows = _run(GUARDED_AUTH)
        self.assertEqual(len(rows), 0, rows)
        self.assertGreaterEqual(acct["candidates_eligible"], 1)  # non-vacuous
        self.assertGreaterEqual(acct["roots_anchored"], 1)

    def test_sanitisation_only_still_fires(self):
        _acct, rows = _run(SANITISATION_ONLY)
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["violation"], "unenforced-root")

    def test_privileged_mover_unguarded_fires(self):
        _acct, rows = _run(PRIV_MOVER_UNGUARDED)
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["property_class"], "conservation")

    def test_self_service_silent(self):
        acct, rows = _run(SELF_SERVICE)
        self.assertEqual(len(rows), 0, rows)

    def test_factory_setup_silent(self):
        _acct, rows = _run(FACTORY_SETUP)
        self.assertEqual(len(rows), 0, rows)

    def test_delegation_cycle_fires(self):
        _acct, rows = _run(DELEGATION_CYCLE)
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["violation"], "delegation-cycle")

    def test_public_grantrole_wrapper_silent(self):
        # public OZ grantRole self-enforces onlyRole(admin) -> wrapper anchored.
        acct, rows = _run(GRANTROLE_PUBLIC_WRAPPER)
        self.assertEqual(len(rows), 0, rows)
        self.assertGreaterEqual(acct["candidates_eligible"], 1)  # non-vacuous

    def test_internal_grantrole_wrapper_fires(self):
        # internal _grantRole is unguarded -> reaching it with no gate is the bug.
        _acct, rows = _run(GRANTROLE_INTERNAL_WRAPPER)
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["violation"], "unenforced-root")
        self.assertEqual(rows[0]["property_class"], "authority")

    def test_swappable_anchor_env_gated(self):
        # OFF by default -> silent (the anchor IS present).
        _acct, rows_off = _run(SWAPPABLE_ANCHOR)
        self.assertEqual(len(rows_off), 0, rows_off)
        # ON via env -> fires swappable-sole-anchor.
        _acct2, rows_on = _run(
            SWAPPABLE_ANCHOR, env={R3._SWAPPABLE_ENV: "1"})
        self.assertEqual(len(rows_on), 1, rows_on)
        self.assertEqual(rows_on[0]["violation"], "swappable-sole-anchor")


class TestR3NonVacuity(unittest.TestCase):
    """Each core predicate is load-bearing: neutralising it flips the planted
    positive's verdict, proving the test is not vacuously green."""

    def test_neutralise_guard_predicate_kills_positive(self):
        orig = R3._has_enforcement_guard
        R3._has_enforcement_guard = lambda fn: True  # everything "anchored"
        try:
            _acct, rows = _run(UNENFORCED_AUTH)
        finally:
            R3._has_enforcement_guard = orig
        self.assertEqual(len(rows), 0, "positive must collapse when guard-pred neutralised")

    def test_neutralise_sink_class_kills_positive(self):
        orig = R3._sink_class
        R3._sink_class = lambda body: None  # nothing severity-eligible
        try:
            _acct, rows = _run(UNENFORCED_AUTH)
        finally:
            R3._sink_class = orig
        self.assertEqual(len(rows), 0, "positive must collapse when eligibility neutralised")

    def test_neutralise_self_auth_makes_selfservice_fire(self):
        orig = R3._is_self_authorizing
        R3._is_self_authorizing = lambda t: False  # disable the FP-guard
        try:
            _acct, rows = _run(SELF_SERVICE)
        finally:
            R3._is_self_authorizing = orig
        self.assertEqual(len(rows), 1, "self-service must fire once its FP-guard is off")


class TestR3FleetFPClean(unittest.TestCase):
    """Advisory-first FP-cleanliness on REAL fleet source (skipped if absent)."""

    def _assert_clean_nonvacuous(self, target: pathlib.Path):
        if not target.exists():
            self.skipTest(f"fleet source absent: {target}")
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            acct = R3.screen(ws, target)
        self.assertEqual(acct["status"], "ok")
        self.assertEqual(acct["rows"], 0, "fleet source must stay SILENT (advisory FP-clean)")
        self.assertGreaterEqual(
            acct["candidates_eligible"], 1,
            "clean run must be NON-VACUOUS (>=1 eligible privileged root examined)")

    def test_reserve_governor_clean(self):
        self._assert_clean_nonvacuous(RESERVE_GOV)

    def test_urd_clean(self):
        self._assert_clean_nonvacuous(URD)


# Morpho fleet FP-clean regression. These four safe-by-design permissionless value-
# movers previously fired (see FIX SPEC): a liquidation gated by
# `require(!_isHealthy(...))` (economic/solvency anchor), interest accrual that mints
# fee shares to FIXED fee recipients (caller gains nothing), and `skim` that moves a
# stray balance to a fixed `skimRecipient`. Each target must be SILENT yet
# NON-VACUOUS (>=1 eligible privileged root examined).
MORPHO_SRC = pathlib.Path("/Users/wolf/audits/morpho/src")
FLEET_FP_TARGETS = {
    "morpho-blue": MORPHO_SRC / "morpho-blue" / "src",   # Morpho.liquidate + .accrueInterest
    "metamorpho": MORPHO_SRC / "metamorpho" / "src",     # MetaMorpho.skim
    "vault-v2": MORPHO_SRC / "vault-v2" / "src",         # VaultV2.accrueInterest
}


class TestR3MorphoFleetFPClean(unittest.TestCase):
    """Regression: the four named fleet FPs must stay 0 (skipped if source absent)."""

    def _run_target(self, target: pathlib.Path):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            acct = R3.screen(ws, target)
            rows = []
            jl = ws / ".auditooor" / R3.OUT_JSONL
            if jl.is_file():
                rows = [json.loads(x) for x in jl.read_text().splitlines() if x.strip()]
        return acct, rows

    def _assert_clean_nonvacuous(self, name: str, target: pathlib.Path):
        if not target.exists():
            self.skipTest(f"fleet source absent: {target}")
        acct, rows = self._run_target(target)
        self.assertEqual(acct["status"], "ok")
        self.assertEqual(
            rows, [],
            f"{name} must stay SILENT (safe-by-design permissionless movers); got {rows}")
        self.assertGreaterEqual(
            acct["candidates_eligible"], 1,
            f"{name} clean run must be NON-VACUOUS (>=1 eligible root examined)")

    def test_morpho_blue_clean(self):
        # Morpho.liquidate (solvency-anchored) + Morpho.accrueInterest (fixed fee dest).
        self._assert_clean_nonvacuous("morpho-blue", FLEET_FP_TARGETS["morpho-blue"])

    def test_metamorpho_clean(self):
        # MetaMorpho.skim -> fixed skimRecipient.
        self._assert_clean_nonvacuous("metamorpho", FLEET_FP_TARGETS["metamorpho"])

    def test_vault_v2_clean(self):
        # VaultV2.accrueInterest -> fixed performance/management fee recipients.
        self._assert_clean_nonvacuous("vault-v2", FLEET_FP_TARGETS["vault-v2"])


class TestR3SolvencyAnchorAndFixedDest(unittest.TestCase):
    """Unit pins for the two new FP-guard mechanisms, plus their non-vacuity: a
    genuinely UNENFORCED permissionless mover (no solvency guard, caller-supplied
    destination) must still FIRE."""

    # a privileged liquidation (acts on ANOTHER account, pulls via transferFrom) gated
    # ONLY by an economic solvency require -> anchored by the invariant (silent).
    SOLVENCY_ANCHORED = """
    pragma solidity ^0.8.0;
    interface IERC20 { function transferFrom(address,address,uint256) external; }
    contract Lender {
        IERC20 token;
        mapping(address => uint256) debt;
        function _isHealthy(address b) internal view returns (bool) { return debt[b] == 0; }
        function liquidate(address borrower, uint256 amt) external {
            require(!_isHealthy(borrower), "healthy");
            debt[borrower] -= amt;
            token.transferFrom(borrower, msg.sender, amt);
        }
    }
    """

    # a permissionless skim-style mover paying a FIXED recipient -> silent.
    FIXED_DEST = """
    pragma solidity ^0.8.0;
    interface IERC20 { function transfer(address,uint256) external returns (bool);
                       function balanceOf(address) external view returns (uint256); }
    contract Vault {
        address feeRecipient;
        function skim(address token) external {
            uint256 amount = IERC20(token).balanceOf(address(this));
            IERC20(token).transfer(feeRecipient, amount);
        }
    }
    """

    # SAME shape but the destination is a CALLER-SUPPLIED param + NO solvency guard ->
    # a genuinely unenforced privileged mover must still FIRE.
    UNENFORCED_MOVER = """
    pragma solidity ^0.8.0;
    interface IERC20 { function transfer(address,uint256) external returns (bool);
                       function balanceOf(address) external view returns (uint256); }
    contract Vault {
        function skimTo(address token, address to) external {
            uint256 amount = IERC20(token).balanceOf(address(this));
            IERC20(token).transfer(to, amount);
        }
    }
    """

    def test_solvency_guard_anchors(self):
        acct, rows = _run(self.SOLVENCY_ANCHORED)
        self.assertEqual(len(rows), 0, rows)
        self.assertGreaterEqual(acct["candidates_eligible"], 1)  # non-vacuous
        self.assertGreaterEqual(acct["roots_anchored"], 1)

    def test_fixed_destination_silent(self):
        _acct, rows = _run(self.FIXED_DEST)
        self.assertEqual(len(rows), 0, rows)

    def test_unenforced_mover_still_fires(self):
        _acct, rows = _run(self.UNENFORCED_MOVER)
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["property_class"], "conservation")

    def test_neutralise_solvency_token_unanchors(self):
        # non-vacuity: strip the solvency tokens from _ENF_COND -> the anchored
        # liquidation collapses back to an unenforced-root positive.
        orig = R3._ENF_COND
        R3._ENF_COND = __import__("re").compile(r"msg\.sender", __import__("re").IGNORECASE)
        try:
            _acct, rows = _run(self.SOLVENCY_ANCHORED)
        finally:
            R3._ENF_COND = orig
        self.assertEqual(len(rows), 1,
                         "solvency-anchored positive must fire once the solvency lexicon is neutralised")


if __name__ == "__main__":
    unittest.main()
