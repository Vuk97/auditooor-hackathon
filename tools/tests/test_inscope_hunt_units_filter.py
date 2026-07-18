#!/usr/bin/env python3
"""Regression: inscope-hunt-batch-builder --units-file restricts the worklist to an
explicit unit allow-list (the hunt-coverage gate's queued_not_scanned), matched on
basename::function. near-intents 2026-06-26: the heatmap-uncovered set != the gate's
queue_units_strict, so a queue-driven worklist is needed to clear the coverage gate."""
import importlib.util, tempfile, unittest
from pathlib import Path
_T = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"
_s = importlib.util.spec_from_file_location("ihbb", _T)
ihbb = importlib.util.module_from_spec(_s); _s.loader.exec_module(ihbb)


class UnitsFilterTest(unittest.TestCase):
    def test_loads_basename_fn_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "u.txt"
            p.write_text("OmniBridge.sol::finTransfer\n"
                         "src/mpc/crates/contract/src/lib.rs::sign\n"
                         "Borsh.sol::encodeAddress(address)\n", encoding="utf-8")
            keys = ihbb._load_units_filter(str(p))
            self.assertIn("omnibridge.sol::fintransfer", keys)
            self.assertIn("lib.rs::sign", keys)          # full path -> basename
            self.assertIn("borsh.sol::encodeaddress", keys)  # paren stripped

    def test_none_when_no_file(self):
        self.assertIsNone(ihbb._load_units_filter(None))
        self.assertIsNone(ihbb._load_units_filter("/nonexistent/x.txt"))

    def test_blank_and_malformed_lines_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "u.txt"
            p.write_text("\nno-colons-here\nFoo.sol::bar\n", encoding="utf-8")
            keys = ihbb._load_units_filter(str(p))
            self.assertEqual(keys, {"foo.sol::bar"})


if __name__ == "__main__":
    unittest.main()
