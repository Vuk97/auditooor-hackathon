#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-FORGE-BUILD-READINESS registered via agent-pathspec-register.py -->
"""Guard: forge-build-readiness-check detects foundry roots, prunes deps, and is
offline-safe (toolchain-absent) - so the per-fn mutation-verify pass can fail
LOUDLY on a broken build instead of silently recording no-execution (0/N).
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "fbr", str(_TOOLS / "forge-build-readiness-check.py"))
fbr = importlib.util.module_from_spec(_spec)
sys.modules["fbr"] = fbr
_spec.loader.exec_module(fbr)


class TestForgeBuildReadiness(unittest.TestCase):
    def _ws(self) -> Path:
        return Path(tempfile.mkdtemp())

    def test_no_foundry_root(self):
        ws = self._ws()
        (ws / "src").mkdir()
        self.assertEqual(fbr.evaluate(ws)["verdict"], "no-foundry-root")

    def test_quarantines_engine_reproducers(self):
        # echidna writes corpus/<name>/foundry/Test.*.sol reproducers that poison
        # `forge build`; they must be moved OUT of the compiled tree (preserved).
        ws = self._ws()
        root = ws / "src" / "ssv"
        repro = root / "test" / "echidna" / "corpus" / "clusters" / "foundry"
        repro.mkdir(parents=True)
        poison = repro / "Test.12345.sol"
        poison.write_text("// malformed reproducer that breaks forge build\n")
        # a normal first-party test file must be left alone
        (root / "test").mkdir(parents=True, exist_ok=True)
        keep = root / "test" / "Real.t.sol"
        keep.write_text("contract R {}\n")
        moved = fbr._quarantine_engine_reproducers(ws, root)
        self.assertTrue(any("Test.12345.sol" in m for m in moved))
        self.assertFalse(poison.exists())  # moved out of compiled tree
        self.assertTrue(keep.exists())     # first-party test untouched
        # preserved under .auditooor quarantine (regenerable but not deleted)
        q = ws / ".auditooor" / "engine_reproducer_quarantine"
        self.assertTrue(any(q.rglob("Test.12345.sol")))

    def test_prunes_node_modules_and_lib(self):
        ws = self._ws()
        (ws / "src" / "ssv").mkdir(parents=True)
        (ws / "src" / "ssv" / "foundry.toml").write_text("[profile.default]\n")
        # foundry.toml inside vendored deps must NOT be picked up as a root
        (ws / "src" / "ssv" / "node_modules" / "x").mkdir(parents=True)
        (ws / "src" / "ssv" / "node_modules" / "x" / "foundry.toml").write_text("x\n")
        (ws / "src" / "ssv" / "lib" / "y").mkdir(parents=True)
        (ws / "src" / "ssv" / "lib" / "y" / "foundry.toml").write_text("y\n")
        roots = fbr._foundry_roots(ws)
        self.assertEqual([str(r.relative_to(ws)) for r in roots], ["src/ssv"])

    def test_toolchain_absent_is_non_fatal(self):
        ws = self._ws()
        (ws / "foundry.toml").write_text("[profile.default]\n")
        orig = fbr._forge_bin
        fbr._forge_bin = lambda: None  # simulate forge not installed
        try:
            r = fbr.evaluate(ws)
        finally:
            fbr._forge_bin = orig
        self.assertEqual(r["verdict"], "toolchain-absent")
        # gate mode must NOT fail-closed when the toolchain is simply absent
        self.assertEqual(fbr.main([str(ws), "--check"]), 0)

    def test_check_mode_fails_only_on_build_broken(self):
        # synthesize a fail-build-broken result and confirm exit semantics
        ws = self._ws()
        (ws / "foundry.toml").write_text("[profile.default]\n")
        orig_eval = fbr.evaluate
        fbr.evaluate = lambda *_a, **_k: {"schema": fbr.SCHEMA, "verdict": "fail-build-broken",
                                          "roots": [{"root": ".", "ok": False, "error_tail": "ParserError"}],
                                          "reason": "x"}
        try:
            self.assertEqual(fbr.main([str(ws), "--check"]), 1)   # fail-closed
            self.assertEqual(fbr.main([str(ws)]), 0)              # advisory (no --check)
        finally:
            fbr.evaluate = orig_eval


if __name__ == "__main__":
    unittest.main(verbosity=2)
