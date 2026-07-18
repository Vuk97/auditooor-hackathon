#!/usr/bin/env python3
"""Regression: hunt-coverage-gate exempts source-confirmed non-public (internal/private)
functions from the queue obligation. queue_units_strict (from exploit_queue) over-includes
library `internal` helpers (Borsh.sol::encodeAddress) and OZ `_pause`-style internals that
are NOT independent unprivileged entrypoints - covered transitively by their public callers.
near-intents 2026-06-26: these sat in queued_not_scanned permanently. Conservative: only
positively-confirmed internal/private decls are exempted (Cairo/unknown never)."""
import importlib.util, tempfile, unittest
from pathlib import Path
_T = Path(__file__).resolve().parent.parent / "hunt-coverage-gate.py"
_s = importlib.util.spec_from_file_location("hcg_np", _T)
hcg = importlib.util.module_from_spec(_s); _s.loader.exec_module(hcg)


class NonPublicExemptTest(unittest.TestCase):
    def _ws(self, tmp, rel, content):
        p = Path(tmp) / "src" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return Path(tmp)

    def test_solidity_internal_exempt(self):
        with tempfile.TemporaryDirectory() as t:
            ws = self._ws(t, "Borsh.sol",
                          "library Borsh {\n  function encodeAddress(address v) internal pure returns (bytes20) { }\n}\n")
            hcg._NONPUBLIC_FILE_CACHE.clear()
            self.assertTrue(hcg._unit_is_nonpublic_internal(ws, "Borsh.sol::encodeAddress"))

    def test_solidity_external_not_exempt(self):
        with tempfile.TemporaryDirectory() as t:
            ws = self._ws(t, "OmniBridge.sol",
                          "contract OmniBridge {\n  function finTransfer(bytes calldata s) external { }\n}\n")
            hcg._NONPUBLIC_FILE_CACHE.clear()
            self.assertFalse(hcg._unit_is_nonpublic_internal(ws, "OmniBridge.sol::finTransfer"))

    def test_solidity_public_not_exempt(self):
        with tempfile.TemporaryDirectory() as t:
            ws = self._ws(t, "X.sol", "contract X {\n  function pause() public { }\n}\n")
            hcg._NONPUBLIC_FILE_CACHE.clear()
            self.assertFalse(hcg._unit_is_nonpublic_internal(ws, "X.sol::pause"))

    def test_rust_private_exempt(self):
        with tempfile.TemporaryDirectory() as t:
            ws = self._ws(t, "lib.rs", "fn helper(x: u64) -> u64 { x }\n")
            hcg._NONPUBLIC_FILE_CACHE.clear()
            self.assertTrue(hcg._unit_is_nonpublic_internal(ws, "lib.rs::helper"))

    def test_rust_pub_not_exempt(self):
        with tempfile.TemporaryDirectory() as t:
            ws = self._ws(t, "lib.rs", "pub fn entry(x: u64) -> u64 { x }\n")
            hcg._NONPUBLIC_FILE_CACHE.clear()
            self.assertFalse(hcg._unit_is_nonpublic_internal(ws, "lib.rs::entry"))

    def test_cairo_never_exempt(self):
        with tempfile.TemporaryDirectory() as t:
            ws = self._ws(t, "borsh.cairo", "fn encode(x: felt252) -> felt252 { x }\n")
            hcg._NONPUBLIC_FILE_CACHE.clear()
            self.assertFalse(hcg._unit_is_nonpublic_internal(ws, "borsh.cairo::encode"))

    def test_unresolvable_not_exempt(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            hcg._NONPUBLIC_FILE_CACHE.clear()
            self.assertFalse(hcg._unit_is_nonpublic_internal(ws, "Nope.sol::ghost"))


if __name__ == "__main__":
    unittest.main()
