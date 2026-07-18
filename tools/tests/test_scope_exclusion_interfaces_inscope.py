"""Regression test for the interfaces/ over-broad test-marker false-green.

BUG (strata, Solidity ERC-4626 DeFi): _TEST_MARKERS_DEFAULT used to carry
"/interface" and "/interfaces/". Because _marker_hit treats a marker containing
"/" as a SUBSTRING test, ANY .sol under an interfaces/ directory was classified
as test/mock infra and DROPPED - even SCOPE.md-enumerated in-scope interface
sources (IRoundDataOracle.sol, IAccessControlManager.sol), yielding
expected-19-got-17. interfaces/ is a normal PRODUCTION Solidity layout (the
declared external surface), NOT test infra.

FIX: the two over-broad markers were removed. Genuine test markers (/test/,
/mock/, /mocks/) must keep firing. These tests pin both directions.
"""
from __future__ import annotations

import unittest

from tools.lib import scope_exclusion as se


class InterfacesInScopeTest(unittest.TestCase):
    def test_interface_dir_no_longer_classified_test(self):
        # SCOPE.md-enumerated in-scope interface sources must NOT be dropped.
        for p in [
            "src/tranches/oracles/interfaces/IRoundDataOracle.sol",
            "src/interfaces/IAccessControlManager.sol",
            "contracts/interface/IFoo.sol",
        ]:
            self.assertFalse(se.is_test(p), f"interface source wrongly test: {p}")
            self.assertFalse(se.is_oos(p), f"interface source wrongly OOS: {p}")
            self.assertFalse(se.is_oos_dir(p), f"interface source wrongly OOS-dir: {p}")
            self.assertTrue(
                se.is_auditable_source(p), f"interface source not auditable: {p}"
            )

    def test_marker_removed_from_table(self):
        markers = se._test_markers()
        self.assertNotIn("/interface", markers)
        self.assertNotIn("/interfaces/", markers)

    def test_genuine_test_markers_still_fire(self):
        # The fix must not weaken real test/mock detection.
        self.assertTrue(se.is_test("src/test/Foo.t.sol"))
        self.assertTrue(se.is_test("contracts/mocks/Mock.sol"))
        self.assertTrue(se.is_test("src/mock/MockOracle.sol"))
        self.assertTrue(se.is_test("test/Foo.t.sol"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
