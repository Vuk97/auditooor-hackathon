#!/usr/bin/env python3
"""Tests for tools/authz-type-exhaustiveness.py - the authz/routing dispatch
type-exhaustiveness screen (RANK-15). Includes the two REQUIRED non-vacuous
mutation pairs (add the missing case with a guard -> survivor disappears; make the
default a safe reject -> survivor disappears)."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "authz-type-exhaustiveness.py"
_spec = importlib.util.spec_from_file_location("authz_type_exhaustiveness", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Fixtures: a Cosmos-style ante dispatch over a proto oneof message universe.
# UNIVERSE = {Msg_Transfer, Msg_Stake, Msg_Admin} (3 declared oneof members).
# The vulnerable dispatch only guards Transfer + Stake and has an UNSAFE default.
# ---------------------------------------------------------------------------
_UNIVERSE_DECLS = """
package types
type Msg_Transfer struct{ Amount uint64 }
type Msg_Stake struct{ Validator string }
type Msg_Admin struct{ Op string }
"""

# a peer switch that proves Msg_Admin is a real member (cross-switch union),
# in case declaration enumeration is not used.
_PEER_SWITCH = """
package keeper
func routeAll(msg interface{}) {
	switch m := msg.(type) {
	case *types.Msg_Transfer:
		_ = m
	case *types.Msg_Stake:
		_ = m
	case *types.Msg_Admin:
		_ = m
	}
}
"""

# VULNERABLE: authz handler, non-exhaustive (no Admin case), UNSAFE default (no
# default -> Admin falls through and is authorized without the check).
_VULN = """
package ante
func (d Decorator) AnteHandle(msg interface{}) error {
	switch m := msg.(type) {
	case *types.Msg_Transfer:
		return d.checkTransfer(m)
	case *types.Msg_Stake:
		return d.checkStake(m)
	}
	return nil
}
"""

# MUTATION 1: add the missing Msg_Admin case WITH a guard -> exhaustive -> no survivor.
_FIX_ADDCASE = """
package ante
func (d Decorator) AnteHandle(msg interface{}) error {
	switch m := msg.(type) {
	case *types.Msg_Transfer:
		return d.checkTransfer(m)
	case *types.Msg_Stake:
		return d.checkStake(m)
	case *types.Msg_Admin:
		return d.checkAdmin(m)
	}
	return nil
}
"""

# MUTATION 2: keep non-exhaustive BUT make the default a safe reject -> no survivor.
_FIX_SAFEDEFAULT = """
package ante
func (d Decorator) AnteHandle(msg interface{}) error {
	switch m := msg.(type) {
	case *types.Msg_Transfer:
		return d.checkTransfer(m)
	case *types.Msg_Stake:
		return d.checkStake(m)
	default:
		return sdkerrors.ErrUnauthorized.Wrap("unhandled message type")
	}
}
"""


def _scan_tree(files: dict):
    """Write files to a temp dir, scan_tree, return (rows, summary)."""
    with tempfile.TemporaryDirectory() as td:
        for name, content in files.items():
            p = Path(td) / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        rows, has_sub, raw = mod.scan_tree(Path(td))
        summ = mod._summary(rows, has_sub, raw)
        return rows, summ


class TestSurvivorDetection(unittest.TestCase):
    def test_survivor_fires_on_nonexhaustive_unsafe_default(self):
        rows, summ = _scan_tree({
            "types/msgs.go": _UNIVERSE_DECLS,
            "keeper/route.go": _PEER_SWITCH,
            "ante/handler.go": _VULN,
        })
        survivors = [r for r in rows if r["survivor"]]
        self.assertEqual(len(survivors), 1, f"expected 1 survivor, got {rows}")
        s = survivors[0]
        self.assertIn("Msg_Admin", s["missing_types"])
        self.assertTrue(s["non_exhaustive"])
        self.assertTrue(s["unsafe_default"])
        self.assertTrue(s["universe_enumerable"])
        self.assertEqual(summ["survivors"], 1)
        self.assertEqual(summ["verdict"], "survivors")

    def test_mutation_add_missing_case_removes_survivor(self):
        """NON-VACUITY PAIR 1: adding the Msg_Admin guarded case makes the dispatch
        exhaustive -> the survivor must disappear."""
        rows, summ = _scan_tree({
            "types/msgs.go": _UNIVERSE_DECLS,
            "keeper/route.go": _PEER_SWITCH,
            "ante/handler.go": _FIX_ADDCASE,
        })
        self.assertEqual(summ["survivors"], 0,
                         f"survivor should vanish after adding case: {rows}")
        # the dispatch is now KEPT (exhaustive)
        anterows = [r for r in rows if r["file"].endswith("ante/handler.go")]
        self.assertEqual(len(anterows), 1)
        self.assertFalse(anterows[0]["non_exhaustive"])
        self.assertEqual(anterows[0]["verdict"], "kept")

    def test_mutation_safe_default_removes_survivor(self):
        """NON-VACUITY PAIR 2: making the default a safe reject (ErrUnauthorized)
        keeps the dispatch non-exhaustive but removes the survivor."""
        rows, summ = _scan_tree({
            "types/msgs.go": _UNIVERSE_DECLS,
            "keeper/route.go": _PEER_SWITCH,
            "ante/handler.go": _FIX_SAFEDEFAULT,
        })
        self.assertEqual(summ["survivors"], 0,
                         f"survivor should vanish after safe default: {rows}")
        anterows = [r for r in rows if r["file"].endswith("ante/handler.go")]
        self.assertEqual(len(anterows), 1)
        self.assertTrue(anterows[0]["non_exhaustive"],
                        "still non-exhaustive (Admin unhandled)")
        self.assertEqual(anterows[0]["default_safety"], "safe-reject")
        self.assertEqual(anterows[0]["verdict"], "kept")


class TestDefaultSafetyClassifier(unittest.TestCase):
    def test_missing_default_is_unsafe(self):
        self.assertEqual(mod.classify_default_safety("", present=False), "unsafe")

    def test_panic_default_is_safe(self):
        self.assertEqual(
            mod.classify_default_safety('panic("unsupported type")', True),
            "safe-reject")

    def test_error_return_default_is_safe(self):
        self.assertEqual(
            mod.classify_default_safety("return sdkerrors.ErrInvalidRequest", True),
            "safe-reject")

    def test_return_nil_default_is_unsafe(self):
        self.assertEqual(mod.classify_default_safety("return nil", True), "unsafe")

    def test_return_next_passthrough_is_unsafe(self):
        self.assertEqual(
            mod.classify_default_safety("return next(ctx, tx, simulate)", True),
            "unsafe")


class TestUniverseEnumeration(unittest.TestCase):
    def test_needs_source_when_universe_not_enumerable(self):
        """A type-switch over an interface with NO oneof family and NO peer switch:
        the universe cannot be enumerated -> advisory needs_source, NOT a survivor."""
        single = """
package ante
func (d Decorator) AnteHandle(msg interface{}) error {
	switch m := msg.(type) {
	case *SomeConcrete:
		return d.check(m)
	}
	return nil
}
"""
        rows, summ = _scan_tree({"ante/handler.go": single})
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertFalse(r["universe_enumerable"])
        self.assertFalse(r["survivor"])
        self.assertEqual(r["advisory"], "needs_source")
        self.assertEqual(summ["needs_source"], 1)

    def test_oneof_family_enumerates_universe(self):
        rows, summ = _scan_tree({
            "types/msgs.go": _UNIVERSE_DECLS,
            "ante/handler.go": _VULN,
        })
        # even without the peer switch, the declared Msg_* family gives the universe
        surv = [r for r in rows if r["survivor"]]
        self.assertEqual(len(surv), 1)
        self.assertIn("Msg_Admin", surv[0]["missing_types"])


class TestSubstrateHonesty(unittest.TestCase):
    def test_idiom_absent_when_no_dispatch(self):
        """Go source with no type-switch / enum at all -> idiom_absent (honest, not
        a tool gap), distinct from substrate_vacuous."""
        rows, summ = _scan_tree({
            "keeper/plain.go": "package keeper\nfunc F() int { return 1 }\n"})
        self.assertEqual(summ["substrate"], "idiom_absent")
        self.assertEqual(summ["verdict"], "no-dispatch")

    def test_authz_irrelevant_switch_is_silent(self):
        """A type-switch in a non-authz helper (pure formatting) is dropped by the
        relevance gate."""
        fmt = """
package prettyprint
func stringify(v interface{}) string {
	switch x := v.(type) {
	case *Foo:
		return x.A
	}
	return ""
}
"""
        rows, summ = _scan_tree({"prettyprint/fmt.go": fmt})
        self.assertEqual(len(rows), 0)


class TestSolidityEnumDispatch(unittest.TestCase):
    def test_solidity_enum_survivor(self):
        sol = """
pragma solidity ^0.8.0;
contract Router {
	enum AssetType { ERC20, ERC721, ERC1155 }
	function route(AssetType t, address to) external {
		if (t == AssetType.ERC20) {
			_handleErc20(to);
		} else if (t == AssetType.ERC721) {
			_handleErc721(to);
		} else {
			_passThrough(to);
		}
	}
}
"""
        rows, summ = _scan_tree({"src/Router.sol": sol})
        surv = [r for r in rows if r["survivor"]]
        self.assertEqual(len(surv), 1, rows)
        self.assertIn("ERC1155", surv[0]["missing_types"])
        self.assertEqual(surv[0]["lang"], "solidity")

    def test_solidity_enum_revert_default_kept(self):
        sol = """
pragma solidity ^0.8.0;
contract Router {
	enum AssetType { ERC20, ERC721, ERC1155 }
	function route(AssetType t, address to) external {
		if (t == AssetType.ERC20) {
			_handleErc20(to);
		} else if (t == AssetType.ERC721) {
			_handleErc721(to);
		} else {
			revert("unsupported asset type");
		}
	}
}
"""
        rows, summ = _scan_tree({"src/Router.sol": sol})
        self.assertEqual(summ["survivors"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
