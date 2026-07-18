"""Loop-fix 2026-06-22: function-coverage-completeness collapsed inscope_units.jsonl
to a FILE set, so a function-scoped file (manifest carries specific in-scope functions)
had EVERY function in it counted - polygon's 1158 in-scope SC functions ballooned to all
functions across their 121 files (~6.5x denominator inflation -> gate unwinnable for the
wrong reason). The new _load_inscope_fn_restrictions honors the manifest's own per-file
granularity: function-level rows restrict to those functions; a file-only row keeps the
whole file (the fork whole-modified-file decision). Must be backward-compatible with a
purely file-level manifest (no restriction == legacy behavior).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "fcc_fng", str(_TOOLS / "function-coverage-completeness.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fcc_fng"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestFnGranularityScope(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, rows):
        ws = Path(tempfile.mkdtemp()).resolve()
        (ws / ".auditooor").mkdir(parents=True)
        with (ws / ".auditooor" / "inscope_units.jsonl").open("w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return ws

    def test_function_level_rows_restrict_to_named_fns(self):
        ws = self._ws([
            {"file": "src/A.sol", "function": "deposit"},
            {"file": "src/A.sol", "function": "withdraw"},
        ])
        r = self.m._load_inscope_fn_restrictions(ws)
        self.assertEqual(r, {"src/A.sol": {"deposit", "withdraw"}})

    def test_file_only_rows_yield_no_restriction(self):
        # Pure file-level manifest (fork whole-file) => None => legacy file-set behavior.
        ws = self._ws([
            {"file": "src/bor/x.go"},
            {"file": "src/bor/y.go"},
        ])
        self.assertIsNone(self.m._load_inscope_fn_restrictions(ws))

    def test_file_only_row_overrides_fn_rows_same_file(self):
        # If a file has BOTH a fn row and a file-only row, the whole file wins.
        ws = self._ws([
            {"file": "src/A.sol", "function": "deposit"},
            {"file": "src/A.sol"},
        ])
        self.assertIsNone(self.m._load_inscope_fn_restrictions(ws))

    def test_mixed_manifest_restricts_only_fn_scoped_file(self):
        ws = self._ws([
            {"file": "src/A.sol", "function": "deposit"},   # SC: fn-level
            {"file": "src/bor/x.go"},                        # fork: whole file
        ])
        self.assertEqual(self.m._load_inscope_fn_restrictions(ws), {"src/A.sol": {"deposit"}})

    def test_env_disable(self):
        import os
        os.environ["AUDITOOOR_FCC_FILE_LEVEL_SCOPE"] = "1"
        try:
            ws = self._ws([{"file": "src/A.sol", "function": "deposit"}])
            self.assertIsNone(self.m._load_inscope_fn_restrictions(ws))
        finally:
            os.environ.pop("AUDITOOOR_FCC_FILE_LEVEL_SCOPE", None)

    def test_keep_logic_end_to_end(self):
        """_keep restricts a fn-scoped file but keeps all in a whole-file entry."""
        ws = self._ws([
            {"file": "src/A.sol", "function": "deposit"},
            {"file": "src/bor/x.go"},
        ])
        inscope = self.m._load_inscope_file_set(ws)
        fns = self.m._load_inscope_fn_restrictions(ws)

        def keep(file, name):
            nf = file.lstrip("./")
            if nf not in inscope:
                return False
            if fns is not None and nf in fns:
                return name in fns[nf]
            return True

        self.assertTrue(keep("src/A.sol", "deposit"))
        self.assertFalse(keep("src/A.sol", "internalHelper"))  # not named => OOS
        self.assertTrue(keep("src/bor/x.go", "anything"))      # whole file => kept
        self.assertFalse(keep("src/OOS.sol", "deposit"))       # file not in manifest


if __name__ == "__main__":
    unittest.main(verbosity=2)
