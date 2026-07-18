#!/usr/bin/env python3
"""test_A10.py - proxy storage-slot-bijection enforcement screen (A10).

Covers tools/proxy-storage-slot-bijection-screen.py, an advisory-first,
NO-AUTO-CREDIT (verdict='needs-fuzz') GENERAL enforcement screen: it flags an
upgradeable contract whose storage-slot bijection across impl versions is
UNENFORCED - raw mutable storage present, but NEITHER a `__gap` reserved array
NOR ERC-7201 namespacing absorbs a future-version storage append.

Non-vacuity / mutation-kill:
  - a PLANTED positive (upgradeable + raw state + no gap/namespace) FIRES;
  - every GUARDED negative (gap present / namespaced / non-upgradeable /
    no-state) stays SILENT;
  - neutralising the CORE predicate (gap detection, or the upgradeable seed)
    flips the guarded/positive outcome, proving each is load-bearing.

Natural fleet instance (read-only, temp-copy only): morpho's real
ERC20Upgradeable (OZ-4.x, `uint256[45] private __gap;`) is SILENT as-is and
FIRES when the __gap line is deleted on a temporary copy.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "proxy-storage-slot-bijection-screen.py"
_ERC20U = Path(
    "/Users/wolf/audits/morpho/src/morpho-blue-bundlers/lib/morpho-utils/lib/"
    "openzeppelin-contracts-upgradeable/contracts/token/ERC20/ERC20Upgradeable.sol"
)


def _load():
    spec = importlib.util.spec_from_file_location("a10_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["a10_screen"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---- synthetic fixtures --------------------------------------------------- #

POSITIVE = """
pragma solidity ^0.8.20;
import {Initializable} from "./Initializable.sol";
// upgradeable base with raw storage and NO gap / NO namespace -> unenforced.
abstract contract VaultBase is Initializable {
    uint256 public totalAssets;
    mapping(address => uint256) internal _shares;
    address public owner;
    function initialize(address o) external initializer { owner = o; }
    function deposit(uint256 a) external { totalAssets += a; }
}
"""

GUARDED_GAP = """
pragma solidity ^0.8.20;
import {Initializable} from "./Initializable.sol";
abstract contract VaultBase is Initializable {
    uint256 public totalAssets;
    mapping(address => uint256) internal _shares;
    address public owner;
    function initialize(address o) external initializer { owner = o; }
    uint256[47] private __gap;
}
"""

GUARDED_NAMESPACE = """
pragma solidity ^0.8.20;
import {Initializable} from "./Initializable.sol";
abstract contract VaultBase is Initializable {
    /// @custom:storage-location erc7201:acme.storage.Vault
    struct VaultStorage { uint256 totalAssets; address owner; }
    bytes32 private constant VaultStorageLocation = 0xdeadbeef00000000000000000000000000000000000000000000000000000000;
    uint256 public legacyCounter;
    function _s() private pure returns (VaultStorage storage $) { assembly { $.slot := VaultStorageLocation } }
    function initialize() external initializer {}
}
"""

NON_UPGRADEABLE = """
pragma solidity ^0.8.20;
contract PlainVault {
    uint256 public totalAssets;
    address public owner;
    constructor(address o) { owner = o; }
}
"""

UPGRADEABLE_NO_STATE = """
pragma solidity ^0.8.20;
import {Initializable} from "./Initializable.sol";
abstract contract Pausable is Initializable {
    function __Pausable_init() internal onlyInitializing {}
    function pause() external {}
}
"""


class TestA10(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _rows(self, src, covered=None):
        return self.m.screen_source(src, path="mem.sol", covered=covered)

    # ---- mutation-kill (synthetic) --------------------------------------
    def test_positive_fires(self):
        rows = self._rows(POSITIVE)
        self.assertEqual(len(rows), 1, "planted positive must fire once")
        r = rows[0]
        self.assertEqual(r["contract"], "VaultBase")
        self.assertEqual(r["canonical_class"], "proxy-storage-slot-bijection")
        self.assertEqual(r["upgradeable_signal"], "inheritance")
        self.assertGreaterEqual(r["state_var_count"], 3)

    def test_guarded_gap_silent(self):
        self.assertEqual(self._rows(GUARDED_GAP), [],
                         "a __gap reserved array must silence the screen")

    def test_guarded_namespace_silent(self):
        self.assertEqual(self._rows(GUARDED_NAMESPACE), [],
                         "ERC-7201 namespacing must silence the screen")

    def test_non_upgradeable_silent(self):
        self.assertEqual(self._rows(NON_UPGRADEABLE), [],
                         "a non-upgradeable contract has no delegated bijection")

    def test_upgradeable_no_state_silent(self):
        self.assertEqual(self._rows(UPGRADEABLE_NO_STATE), [],
                         "no raw storage -> no bijection to corrupt")

    # ---- NO-AUTO-CREDIT verdict contract --------------------------------
    def test_verdict_is_needs_fuzz_no_auto_credit(self):
        for r in self._rows(POSITIVE):
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertFalse(r["auto_credit"])

    # ---- load-bearing: gap predicate ------------------------------------
    def test_gap_predicate_is_load_bearing(self):
        # neutralise gap detection -> the GUARDED-gap fixture must now FIRE,
        # proving the gap is what suppresses it (not a vacuous always-empty).
        saved = self.m._A10_GAP_RE
        try:
            self.m._A10_GAP_RE = re.compile(r"ZZZ_NEVER_MATCHES")
            rows = self._rows(GUARDED_GAP)
            self.assertEqual(len(rows), 1,
                             "neutralising __gap detection must expose the guarded fixture")
            self.assertEqual(rows[0]["contract"], "VaultBase")
        finally:
            self.m._A10_GAP_RE = saved
        self.assertEqual(self._rows(GUARDED_GAP), [], "restored gap re-silences")

    # ---- load-bearing: namespace predicate ------------------------------
    def test_namespace_predicate_is_load_bearing(self):
        saved = self.m._A10_NAMESPACE_RE
        try:
            self.m._A10_NAMESPACE_RE = re.compile(r"ZZZ_NEVER_MATCHES")
            rows = self._rows(GUARDED_NAMESPACE)
            self.assertEqual(len(rows), 1,
                             "neutralising namespace detection must expose the fixture")
        finally:
            self.m._A10_NAMESPACE_RE = saved
        self.assertEqual(self._rows(GUARDED_NAMESPACE), [], "restored namespace re-silences")

    # ---- load-bearing: upgradeable seed ---------------------------------
    def test_upgradeable_seed_is_load_bearing(self):
        saved_inh = self.m._A10_UPGRADEABLE_INHERIT_RE
        saved_body = self.m._A10_UPGRADEABLE_BODY_RE
        try:
            self.m._A10_UPGRADEABLE_INHERIT_RE = re.compile(r"ZZZ_NEVER_MATCHES")
            self.m._A10_UPGRADEABLE_BODY_RE = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(self._rows(POSITIVE), [],
                             "no upgradeable seed -> no A10 hypothesis")
        finally:
            self.m._A10_UPGRADEABLE_INHERIT_RE = saved_inh
            self.m._A10_UPGRADEABLE_BODY_RE = saved_body
        self.assertEqual(len(self._rows(POSITIVE)), 1)

    # ---- library / interface never flagged ------------------------------
    def test_library_and_interface_silent(self):
        lib = ("pragma solidity ^0.8.20;\nlibrary L {\n"
               "  function f() internal pure returns (uint256) { return 1; }\n}\n")
        iface = ("pragma solidity ^0.8.20;\ninterface I is Initializable {\n"
                 "  function initialize() external;\n}\n")
        self.assertEqual(self._rows(lib), [])
        self.assertEqual(self._rows(iface), [])

    # ---- DEDUP boundary (A1): consume covered, never re-derive ----------
    def test_dedup_covered_by_consumed(self):
        r0 = self._rows(POSITIVE)
        self.assertFalse(r0[0]["covered_by"])
        r1 = self._rows(POSITIVE, covered={("VaultBase", "totalAssets")})
        self.assertTrue(r1[0]["covered_by"])
        r2 = self._rows(POSITIVE, covered={"VaultBase"})
        self.assertTrue(r2[0]["covered_by"])
        r3 = self._rows(POSITIVE, covered=lambda k: k[0] == "VaultBase")
        self.assertTrue(r3[0]["covered_by"])

    # ---- advisory-first gate (OFF by default) ---------------------------
    def test_advisory_off_by_default(self):
        os.environ.pop(self.m._A10_ENV, None)
        self.assertFalse(self.m._a10_advisory_enabled())

    def test_advisory_on_when_env_set(self):
        os.environ[self.m._A10_ENV] = "1"
        try:
            self.assertTrue(self.m._a10_advisory_enabled())
        finally:
            os.environ.pop(self.m._A10_ENV, None)

    # ---- directory / file scan convenience ------------------------------
    def test_path_scan(self):
        d = Path(tempfile.mkdtemp())
        (d / "pos.sol").write_text(POSITIVE)
        (d / "gap.sol").write_text(GUARDED_GAP)
        rows = self.m.screen_path(d)
        contracts = {r["contract"] for r in rows}
        self.assertIn("VaultBase", contracts)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in rows))
        # exactly one fires (pos.sol); gap.sol is silent.
        self.assertEqual(len(rows), 1)

    # ---- natural fleet instance (read-only, temp copy only) -------------
    @unittest.skipUnless(_ERC20U.is_file(), "morpho ws not present on this host")
    def test_natural_instance_erc20upgradeable(self):
        src = _ERC20U.read_text()
        # BENIGN as-is: has `uint256[45] private __gap;` -> silent.
        self.assertEqual(
            self.m.screen_source(src, path=str(_ERC20U)), [],
            "OZ ERC20Upgradeable with its __gap must be silent")
        # MUTANT on a TEMP COPY: delete the gap line -> unenforced -> fires.
        mut = re.sub(r"uint256\[45\] private __gap;", "", src, count=1)
        self.assertNotEqual(mut, src, "mutation must apply")
        d = Path(tempfile.mkdtemp())
        p = d / "ERC20Upgradeable_mut.sol"
        p.write_text(mut)
        rows = self.m.screen_source(mut, path=str(p))
        self.assertEqual(len(rows), 1, "gap-weakened copy must fire once")
        self.assertEqual(rows[0]["contract"], "ERC20Upgradeable")
        self.assertEqual(rows[0]["verdict"], "needs-fuzz")
        self.assertFalse(rows[0]["auto_credit"])


if __name__ == "__main__":
    unittest.main()
