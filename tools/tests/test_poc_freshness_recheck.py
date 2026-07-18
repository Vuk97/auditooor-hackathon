#!/usr/bin/env python3
"""NUVA 2026-06-30: a filed finding's PoC silently stopped compiling when the
audited source renamed a struct field (VaultAccount.FeePeriodStart->PeriodStart);
nothing re-validated it. poc-freshness-recheck re-vets each paste-ready/filed PoC
against current src. Pins the pure logic: package resolution, drift classification,
and module discovery (the go-vet invocation is integration-tested live on NUVA).
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "poc-freshness-recheck.py"


def _load():
    spec = importlib.util.spec_from_file_location("pfr", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["pfr"] = m
    spec.loader.exec_module(m)
    return m


pfr = _load()


class PocFreshnessTest(unittest.TestCase):
    def test_go_package_of_strips_test_suffix(self):
        self.assertEqual(pfr.go_package_of("package keeper_test\n"), "keeper")
        self.assertEqual(pfr.go_package_of("package keeper\n"), "keeper")
        self.assertIsNone(pfr.go_package_of("// no package line\n"))

    def test_classify_drift_detects_renamed_symbol(self):
        out = ("vet: keeper/x_test.go:388:8: vault.FeePeriodStart undefined "
               "(type *types.VaultAccount has no field or method FeePeriodStart)")
        sigs = pfr.classify_drift(out)
        self.assertTrue(any("FeePeriodStart" in s for s in sigs))

    def test_classify_drift_ignores_clean_output(self):
        self.assertEqual(pfr.classify_drift("ok  module/keeper  0.5s\n"), [])

    def test_resolve_go_pkg_dir_finds_declaring_dir(self):
        d = Path(tempfile.mkdtemp(prefix="pfr_mod_"))
        (d / "keeper").mkdir()
        (d / "keeper" / "vault.go").write_text("package keeper\nfunc F(){}\n")
        (d / "types").mkdir()
        (d / "types" / "v.go").write_text("package types\n")
        self.assertEqual(pfr.resolve_go_pkg_dir(d, "keeper"), d / "keeper")
        self.assertIsNone(pfr.resolve_go_pkg_dir(d, "nonexistent"))

    def test_find_go_module_roots(self):
        ws = Path(tempfile.mkdtemp(prefix="pfr_ws_"))
        (ws / "src" / "vault").mkdir(parents=True)
        (ws / "src" / "vault" / "go.mod").write_text("module x\n")
        self.assertEqual(pfr.find_go_module_roots(ws), [ws / "src" / "vault"])

    def test_recheck_reports_unplaceable_pkg_as_note_not_crash(self):
        ws = Path(tempfile.mkdtemp(prefix="pfr_ws2_"))
        (ws / "submissions" / "paste_ready" / "f").mkdir(parents=True)
        (ws / "submissions" / "paste_ready" / "f" / "x_test.go").write_text(
            "package ghost_test\nfunc TestX(){}\n")
        r = pfr.recheck(ws)
        self.assertEqual(r["poc_count"], 1)
        self.assertIsNone(r["results"][0]["compiles"])  # unplaceable -> not a false stale
        self.assertEqual(r["verdict"], "pass-poc-fresh")


class BaselineDiffTest(unittest.TestCase):
    """The package-wide vet must not blame the PoC for a sibling test's ambient nit."""

    def _mk_module_with_poc(self):
        ws = Path(tempfile.mkdtemp(prefix="pfr_bd_"))
        mod = ws / "src" / "vault"
        (mod / "keeper").mkdir(parents=True)
        (mod / "go.mod").write_text("module x\n")
        (mod / "keeper" / "k.go").write_text("package keeper\nfunc F(){}\n")
        poc = ws / "poc_test.go"
        poc.write_text("package keeper_test\nfunc TestX(){}\n")
        return ws, mod, poc

    def test_ambient_sibling_nit_not_attributed_to_poc(self):
        ws, mod, poc = self._mk_module_with_poc()
        AMBIENT = "keeper/payout_test.go:521:19: Coin struct literal uses unkeyed fields"
        calls = {"n": 0}
        def fake_compile(pkg_dir, mod_root):
            calls["n"] += 1
            # baseline AND with-poc both have the SAME ambient nit -> no new drift
            return False, AMBIENT + "\n"
        orig = pfr._go_compile_check
        pfr._go_compile_check = fake_compile
        try:
            r = pfr.recheck_go_poc(ws, poc, [mod])
        finally:
            pfr._go_compile_check = orig
        self.assertTrue(r["compiles"], "ambient sibling nit must NOT mark the PoC stale")
        self.assertEqual(r["drift"], [])

    def test_new_renamed_symbol_is_flagged(self):
        ws, mod, poc = self._mk_module_with_poc()
        AMBIENT = "keeper/payout_test.go:521: unkeyed fields"
        DRIFT = "keeper/_pocfresh_poc_test.go:5: vault.FeePeriodStart undefined (has no field or method FeePeriodStart)"
        state = {"with": False}
        def fake_compile(pkg_dir, mod_root):
            # first call = baseline (ambient only); second = with PoC (ambient + drift)
            if not state["with"]:
                state["with"] = True
                return False, AMBIENT + "\n"
            return False, AMBIENT + "\n" + DRIFT + "\n"
        orig = pfr._go_compile_check
        pfr._go_compile_check = fake_compile
        try:
            r = pfr.recheck_go_poc(ws, poc, [mod])
        finally:
            pfr._go_compile_check = orig
        self.assertFalse(r["compiles"], "a NEW undefined-symbol must mark the PoC stale")
        self.assertTrue(any("FeePeriodStart" in d for d in r["drift"]))
        self.assertFalse(any("payout_test" in d for d in r["drift"]),
                         "ambient nit must not appear in PoC drift")


if __name__ == "__main__":
    unittest.main(verbosity=2)
