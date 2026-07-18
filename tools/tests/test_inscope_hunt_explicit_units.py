#!/usr/bin/env python3
"""Regression: inscope-hunt-batch-builder --units-file resolves + body-extracts queued
units ON-DEMAND from source, reaching units ABSENT from the completeness list (the
under-extracted Cairo/internal tail). near-intents 2026-06-26: --units-file via the
completeness filter could not emit tasks for Cairo borsh encoders; the explicit builder
resolves them directly from source."""
import importlib.util, tempfile, unittest
from pathlib import Path
_T = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"
_s = importlib.util.spec_from_file_location("ihbb_x", _T)
ihbb = importlib.util.module_from_spec(_s); _s.loader.exec_module(ihbb)


class ExplicitUnitsTest(unittest.TestCase):
    def _ws(self, tmp):
        ws = Path(tmp) / "ws"
        (ws / "src" / "cairo").mkdir(parents=True)
        (ws / "src" / "cairo" / "borsh.cairo").write_text(
            "fn encode_u32(v: u32) -> felt252 {\n  v.into()\n}\n", encoding="utf-8")
        (ws / "src" / "evm").mkdir(parents=True)
        (ws / "src" / "evm" / "Borsh.sol").write_text(
            "library Borsh {\n  function encodeAddress(address v) internal pure returns (bytes20) {\n    return bytes20(v);\n  }\n}\n",
            encoding="utf-8")
        return ws

    def test_resolves_cairo_and_sol_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            uf = Path(tmp) / "u.txt"
            uf.write_text("borsh.cairo::encode_u32\nBorsh.sol::encodeAddress\n", encoding="utf-8")
            tasks, err = ihbb.build_tasks_from_units_explicit(ws, str(uf))
            self.assertIsNone(err)
            fns = {t["function_anchor"]["fn"] for t in tasks}
            self.assertEqual(fns, {"encode_u32", "encodeAddress"})
            for t in tasks:
                self.assertGreater(t["function_anchor"]["start_line"], 0)
                self.assertTrue(t["body_embedded"])

    def test_missing_file_skipped_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            uf = Path(tmp) / "u.txt"
            uf.write_text("Ghost.sol::nope\nborsh.cairo::encode_u32\n", encoding="utf-8")
            tasks, err = ihbb.build_tasks_from_units_explicit(ws, str(uf))
            self.assertIsNone(err)
            self.assertEqual(len(tasks), 1)

    def test_missing_units_file_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            tasks, err = ihbb.build_tasks_from_units_explicit(Path(tmp), "/no/such.txt")
            self.assertIsNone(tasks)
            self.assertIn("not found", err)


    def test_file_only_unit_emits_first_function(self):
        # a FILE-ONLY queue entry (no ::) is a whole-file obligation; the builder must
        # still emit a task (the file's first fn) so hunting it credits the file.
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "src" / "x").mkdir(parents=True)
            (ws / "src" / "x" / "account_id.rs").write_text(
                "use foo;\nfn parse(a: u8) -> u8 { a }\nfn other() {}\n", encoding="utf-8")
            uf = Path(tmp) / "u.txt"
            uf.write_text("account_id.rs\n", encoding="utf-8")  # no ::
            tasks, err = ihbb.build_tasks_from_units_explicit(ws, str(uf))
            self.assertIsNone(err)
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0]["function_anchor"]["fn"], "parse")
            self.assertGreater(tasks[0]["function_anchor"]["start_line"], 0)

if __name__ == "__main__":
    unittest.main()
