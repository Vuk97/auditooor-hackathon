"""Regression: return-aliasing-escape honors the in-scope manifest.

Root-caused 2026-07-14: the engine filtered files only by suffix (_test.go/.pb.go)
and NOT by inscope_units.jsonl, so it walked OOS simapp/ / simulation/ / cmd/ and
emitted ~23 out-of-scope return-aliasing false-reds on nuva (SimApp.LegacyAmino,
NewRootCmd, sim rand) - files correctly ABSENT from the manifest. Fix: when the
manifest is present, only walk files it lists. Conservative: an absent/empty
manifest applies NO filter, so scope-less runs are unchanged (no over-exclusion).
"""
import importlib.util
import json
import pathlib
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "return-aliasing-escape.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("rae_scope_test", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestReturnAliasingInscopeFilter(unittest.TestCase):
    def setUp(self):
        self.m = _load_mod()
        self.tmp = tempfile.mkdtemp(prefix="raescope_")
        self.ws = pathlib.Path(self.tmp)
        (self.ws / ".auditooor").mkdir(parents=True)
        # in-scope keeper file + OOS simapp file
        (self.ws / "src" / "vault" / "keeper").mkdir(parents=True)
        (self.ws / "src" / "vault" / "simapp").mkdir(parents=True)
        self.inscope_go = self.ws / "src" / "vault" / "keeper" / "vault.go"
        self.inscope_go.write_text("package keeper\nfunc F() {}\n")
        self.oos_go = self.ws / "src" / "vault" / "simapp" / "app.go"
        self.oos_go.write_text("package simapp\nfunc G() {}\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_manifest(self, rels):
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps({"file": r}) for r in rels))

    def test_manifest_present_filters_oos(self):
        self._write_manifest(["src/vault/keeper/vault.go"])
        inscope = self.m._load_inscope_go(self.ws)
        self.assertIn("src/vault/keeper/vault.go", inscope)
        files = self.m._iter_go_files(self.ws, ws=self.ws, inscope=inscope)
        names = {p.name for p in files}
        self.assertIn("vault.go", names, "in-scope keeper file must be walked")
        self.assertNotIn("app.go", names, "OOS simapp file must be filtered out")

    def test_no_manifest_walks_everything(self):
        # empty manifest -> no filter -> both files walked (conservative)
        inscope = self.m._load_inscope_go(self.ws)  # file absent -> empty set
        self.assertEqual(inscope, set())
        files = self.m._iter_go_files(self.ws, ws=self.ws, inscope=inscope)
        names = {p.name for p in files}
        self.assertEqual({"vault.go", "app.go"}, names,
                         "no manifest => walk everything (no over-exclusion)")

    def test_still_skips_generated_and_test(self):
        (self.ws / "src" / "vault" / "keeper" / "x_test.go").write_text("package keeper\n")
        self._write_manifest(["src/vault/keeper/vault.go", "src/vault/keeper/x_test.go"])
        inscope = self.m._load_inscope_go(self.ws)
        files = self.m._iter_go_files(self.ws, ws=self.ws, inscope=inscope)
        names = {p.name for p in files}
        self.assertNotIn("x_test.go", names, "_test.go stays skipped even if manifest lists it")


if __name__ == "__main__":
    unittest.main()
