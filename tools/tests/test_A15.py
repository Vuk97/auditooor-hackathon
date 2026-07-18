#!/usr/bin/env python3
"""A15 stale-grant-survival screen - regression + mutation (non-vacuity).

Pins tools/stale-grant-survival-screen.py, the general lifecycle invariant
"a standing grant scoped to a replaceable module reference must be revoked at
the point that reference is swapped". Pure-regex (no Slither), so fixtures are
inline source strings.

Matrix (the invariant VIOLATED fires; HELD / N-A is SILENT):
  - grant + module swapped WITHOUT revoke of old grantee   -> 1 violator.
  - grant + module swapped WITH revoke (guarded)           -> 0 (invariant holds).
  - grant to an immutable/never-swapped module (Escrow)    -> 0 (nothing to strand).
  - grant to a `constant` grantee                          -> 0 (unswappable).
  - grantee reassigned only in constructor/initialize      -> 0 (first-init, not a swap).
  - grant to a non-module (fn param / msg.sender)          -> 0 (not a stored reference).
  - operator (setApprovalForAll) grant swapped no-revoke   -> 1 violator.
  - role (grantRole) grant swapped no-revoke               -> 1 violator.

Non-vacuity (the core predicate is load-bearing - neutralising it flips the
verdict): forcing `swap_revokes_old_grant` to always return True makes the
planted POSITIVE stop firing (the test asserts the collapse).
"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

TOOLS = pathlib.Path(__file__).resolve().parents[1]


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "stale_grant_survival_screen", TOOLS / "stale-grant-survival-screen.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load_tool()


# ---- fixtures --------------------------------------------------------------
POS_ALLOWANCE_SWAP = """
pragma solidity ^0.8.0;
contract Vault {
    IERC20 public asset;
    address public adapter;            // replaceable module reference
    constructor(IERC20 a, address adp) { asset = a; adapter = adp;
        asset.approve(adapter, type(uint256).max); }
    function setAdapter(address newAdapter) external onlyOwner {
        adapter = newAdapter;          // SWAP: old adapter keeps max allowance
    }
}
"""

NEG_ALLOWANCE_SWAP_REVOKED = """
pragma solidity ^0.8.0;
contract Vault {
    IERC20 public asset;
    address public adapter;
    constructor(IERC20 a, address adp) { asset = a; adapter = adp;
        asset.approve(adapter, type(uint256).max); }
    function setAdapter(address newAdapter) external onlyOwner {
        asset.approve(adapter, 0);     // revoke OLD grantee first (guarded)
        adapter = newAdapter;
    }
}
"""

NEG_IMMUTABLE_NEVER_SWAPPED = """
pragma solidity ^0.8.0;
contract Escrow {
    IStETH public immutable ST_ETH;
    IWithdrawalQueue public immutable WITHDRAWAL_QUEUE;
    constructor(IStETH s, IWithdrawalQueue q) { ST_ETH = s; WITHDRAWAL_QUEUE = q; }
    function initialize() external {
        ST_ETH.approve(address(WITHDRAWAL_QUEUE), type(uint256).max);
    }
}
"""

NEG_CONSTANT_GRANTEE = """
pragma solidity ^0.8.0;
contract C {
    IERC20 public asset;
    address public constant SINK = 0x000000000000000000000000000000000000dEaD;
    function go() external { asset.approve(SINK, type(uint256).max); }
    function setSink(address x) external { /* SINK is constant, cannot swap */ }
}
"""

NEG_INIT_ONLY_REASSIGN = """
pragma solidity ^0.8.0;
contract C {
    IERC20 public asset;
    address public router;
    function initialize(address r) external {
        router = r;                       // first-init, not a swap
        asset.approve(router, type(uint256).max);
    }
}
"""

NEG_NON_MODULE_GRANTEE = """
pragma solidity ^0.8.0;
contract C {
    IERC20 public asset;
    address public router;
    function pull(address spender) external {
        asset.approve(spender, type(uint256).max);  // grantee is a param
    }
    function setRouter(address r) external { router = r; }  // router never granted
}
"""

# --- etherfi FP regression fixtures ----------------------------------------
# (a) grantee declared as a STRUCT FIELD (not contract storage) + reassigned as
#     a named-return LOCAL inside a view fn. Mirrors SettlementDispatcherV2's
#     `address stargate` field in `DestinationData` -> must be SILENT.
NEG_STRUCT_FIELD_GRANTEE = """
pragma solidity ^0.8.0;
contract C {
    struct DestinationData {
        uint32 destEid;
        address stargate;                 // struct field, NOT contract storage
    }
    mapping(address => DestinationData) data;
    function bridge(address token, uint256 amount) external {
        DestinationData memory d = data[token];
        address stargate = d.stargate;    // local
        IERC20(token).forceApprove(stargate, amount);   // grant to a LOCAL
    }
    function prep(address token) public view returns (address stargate) {
        stargate = data[token].stargate;  // reassign named-return in a VIEW fn
    }
}
"""

# (b) real storage module var, granted, but the ONLY reassignment is a
#     same-named named-return inside a VIEW function -> not a storage swap.
NEG_VIEW_NAMED_RETURN = """
pragma solidity ^0.8.0;
contract C {
    IERC20 public asset;
    address public router;
    constructor(address r) { router = r; asset.approve(router, type(uint256).max); }
    function peek() external view returns (address router) {
        router = address(0x1234);         // named-return shadow in a view fn
    }
}
"""

# (c) grantee reassigned only inside a `_setup`-prefixed init function ->
#     first-init, not a swap.
NEG_SETUP_INIT = """
pragma solidity ^0.8.0;
contract C {
    IERC20 public asset;
    address public router;
    function _setupRouter(address r) internal {
        router = r;                        // setup-prefixed init, not a swap
        asset.approve(router, type(uint256).max);
    }
}
"""

POS_OPERATOR_SWAP = """
pragma solidity ^0.8.0;
contract C {
    IERC721 public nft;
    address public operator;
    constructor(IERC721 n, address op) { nft = n; operator = op;
        nft.setApprovalForAll(operator, true); }
    function rotate(address newOp) external { operator = newOp; }
}
"""

POS_ROLE_SWAP = """
pragma solidity ^0.8.0;
contract C is AccessControl {
    address public module;
    constructor(address m) { module = m; _grantRole(MINTER_ROLE, module); }
    function setModule(address newModule) external { module = newModule; }
}
"""


def _fire_count(src):
    return len(MOD.analyze_source(src, "T.sol"))


class TestA15Matrix(unittest.TestCase):
    def test_positive_allowance_swap_fires(self):
        v = MOD.analyze_source(POS_ALLOWANCE_SWAP, "T.sol")
        self.assertEqual(len(v), 1, v)
        self.assertEqual(v[0]["grantee_var"], "adapter")
        self.assertEqual(v[0]["grant_kind"], "allowance")
        self.assertEqual(v[0]["swapped_in"], "setAdapter")
        self.assertEqual(v[0]["verdict"], "needs-fuzz")   # advisory-first

    def test_guarded_swap_silent(self):
        self.assertEqual(_fire_count(NEG_ALLOWANCE_SWAP_REVOKED), 0)

    def test_immutable_never_swapped_silent(self):
        self.assertEqual(_fire_count(NEG_IMMUTABLE_NEVER_SWAPPED), 0)

    def test_constant_grantee_silent(self):
        self.assertEqual(_fire_count(NEG_CONSTANT_GRANTEE), 0)

    def test_init_only_reassign_silent(self):
        self.assertEqual(_fire_count(NEG_INIT_ONLY_REASSIGN), 0)

    def test_non_module_grantee_silent(self):
        self.assertEqual(_fire_count(NEG_NON_MODULE_GRANTEE), 0)

    def test_struct_field_grantee_silent(self):
        # etherfi SettlementDispatcherV2 FP: `address stargate` is a struct field
        self.assertEqual(_fire_count(NEG_STRUCT_FIELD_GRANTEE), 0)

    def test_view_named_return_silent(self):
        # a view fn cannot write storage -> its named-return `=` is not a swap
        self.assertEqual(_fire_count(NEG_VIEW_NAMED_RETURN), 0)

    def test_setup_prefixed_init_silent(self):
        self.assertEqual(_fire_count(NEG_SETUP_INIT), 0)

    def test_operator_swap_fires(self):
        v = MOD.analyze_source(POS_OPERATOR_SWAP, "T.sol")
        self.assertEqual(len(v), 1, v)
        self.assertEqual(v[0]["grant_kind"], "operator")

    def test_role_swap_fires(self):
        v = MOD.analyze_source(POS_ROLE_SWAP, "T.sol")
        self.assertEqual(len(v), 1, v)
        self.assertEqual(v[0]["grant_kind"], "role")


class TestA15NonVacuity(unittest.TestCase):
    """Neutralising the load-bearing predicate must collapse the positive."""

    def test_neutralised_core_predicate_stops_positive(self):
        # sanity: positive fires with the real predicate
        self.assertEqual(_fire_count(POS_ALLOWANCE_SWAP), 1)
        orig = MOD.swap_revokes_old_grant
        try:
            # force "the swap always revokes" -> the enforcer can never flag
            MOD.swap_revokes_old_grant = lambda *a, **k: True
            self.assertEqual(
                _fire_count(POS_ALLOWANCE_SWAP), 0,
                "positive still fired after neutralising swap_revokes_old_grant "
                "-> predicate is not load-bearing (vacuous test)")
        finally:
            MOD.swap_revokes_old_grant = orig
        # and it fires again once restored
        self.assertEqual(_fire_count(POS_ALLOWANCE_SWAP), 1)

    def test_advisory_first_never_fails_closed(self):
        # empty / grant-free source -> no rows, no exception, no gate flip
        hyps, acc = MOD.run([], root=None)
        self.assertEqual(hyps, [])
        self.assertFalse(acc["auto_credit"])
        self.assertTrue(acc["advisory_first"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
