#!/usr/bin/env python3
"""capability-v3 iter-001 T4 — ERC4626 vault campaign regression suite.

Four tests:
  1. Auto-detect ERC4626 interface (positive on vault_good, negative on
     vault_not_a_vault).
  2. Campaign writes 5 invariant harnesses to poc-tests/invariants/
     when invoked on vault_good.
  3. Mocked fuzz runner returning all-pass -> campaign report shows 5/5.
  4. Mocked fuzz runner returning a counterexample on I4 -> campaign
     report flags it.

No real forge / fuzz engine is invoked; the task explicitly calls for
mocked-runner regression so the suite runs offline in CI.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "attach-invariant.py"
CAMPAIGN_MOD_PATH = ROOT / "tools" / "invariants" / "campaign" / "vault_erc4626.py"
FIX_GOOD = ROOT / "tools" / "tests" / "fixtures" / "vault_good"
FIX_BAD = ROOT / "tools" / "tests" / "fixtures" / "vault_bad"
FIX_NOT_VAULT = ROOT / "tools" / "tests" / "fixtures" / "vault_not_a_vault"


def _load(path: Path, modname: str):
    """Path-based module loader — tools/ is not a package in this repo."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(modname, path)
    assert spec and spec.loader, f"cannot load {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_campaign_mod():
    return _load(CAMPAIGN_MOD_PATH, "_t_vault_erc4626")


def _load_attach_mod():
    return _load(TOOL, "_t_attach_invariant")


def _run(*args):
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
    )


def _copy_ws(src: Path) -> Path:
    """Copy a fixture workspace into a tempdir and return the new path.

    Emitter writes into <ws>/poc-tests/invariants/, so we need a
    disposable workspace per test to avoid cross-test contamination.
    """
    td = Path(tempfile.mkdtemp())
    dest = td / src.name
    shutil.copytree(src, dest)
    return dest


class TestAutoDetectERC4626(unittest.TestCase):
    """Positive on vault_good, negative on a non-vault workspace."""

    def test_positive_detects_vault_good(self):
        vault_erc4626 = _load_campaign_mod()

        src = (FIX_GOOD / "src" / "Vault.sol").read_text()
        ok, missing = vault_erc4626.detect_erc4626(src)
        self.assertTrue(ok, f"vault_good must pass detection; missing: {missing}")
        self.assertEqual(missing, [])

    def test_positive_detects_vault_bad(self):
        vault_erc4626 = _load_campaign_mod()

        src = (FIX_BAD / "src" / "Vault.sol").read_text()
        ok, _ = vault_erc4626.detect_erc4626(src)
        self.assertTrue(ok, "vault_bad is still an ERC4626 shape — must detect")

    def test_negative_rejects_non_vault(self):
        vault_erc4626 = _load_campaign_mod()

        src = (FIX_NOT_VAULT / "src" / "Counter.sol").read_text()
        ok, missing = vault_erc4626.detect_erc4626(src)
        self.assertFalse(ok, "Counter.sol must not be mis-detected as ERC4626")
        # Every required method must show up in `missing`.
        for m in vault_erc4626.ERC4626_REQUIRED_METHODS:
            self.assertIn(m, missing)

    def test_campaign_cli_refuses_non_vault(self):
        """CLI hard-negative: --mode campaign exits non-zero on non-vault."""
        ws = _copy_ws(FIX_NOT_VAULT)
        try:
            res = _run(str(ws), "--family", "vault", "--mode", "campaign")
            self.assertEqual(res.returncode, 2, res.stderr)
            self.assertIn("requires an ERC4626", res.stderr)
            # Must not have written any harnesses.
            out = ws / "poc-tests" / "invariants"
            self.assertFalse(
                out.exists() and any(out.iterdir()),
                "no harnesses should be written on hard-negative",
            )
        finally:
            shutil.rmtree(ws.parent, ignore_errors=True)


class TestCampaignWritesFiveInvariants(unittest.TestCase):
    """After running on vault_good, 5 .t.sol files exist."""

    def test_five_harnesses_emitted(self):
        ws = _copy_ws(FIX_GOOD)
        try:
            res = _run(
                str(ws), "--family", "vault", "--mode", "campaign",
                "--contract", "Vault",
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            out = ws / "poc-tests" / "invariants"
            emitted = sorted(p.name for p in out.glob("vault_campaign_I*.t.sol"))
            self.assertEqual(
                emitted,
                [
                    "vault_campaign_I1.t.sol",
                    "vault_campaign_I2.t.sol",
                    "vault_campaign_I3.t.sol",
                    "vault_campaign_I4.t.sol",
                    "vault_campaign_I5.t.sol",
                ],
            )
            # Banner rule: every file must carry the truth-audit header.
            for p in out.glob("vault_campaign_I*.t.sol"):
                body = p.read_text()
                self.assertIn("CANDIDATE HARNESS", body, f"{p} missing banner")
                self.assertIn("NOT PROOF", body, f"{p} missing banner")
                self.assertIn("invariant_", body, f"{p} missing invariant_")
                # Contract-name substitution must have happened.
                self.assertNotIn("{ContractName}", body, f"{p} unsubstituted")
                self.assertIn("Vault", body)
        finally:
            shutil.rmtree(ws.parent, ignore_errors=True)


class TestCampaignReportMocked(unittest.TestCase):
    """Campaign aggregation against a mocked runner."""

    def _emit(self, fixture: Path) -> Path:
        ws = _copy_ws(fixture)
        res = _run(
            str(ws), "--family", "vault", "--mode", "campaign",
            "--contract", "Vault",
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        return ws

    def test_good_fixture_all_pass_mocked(self):
        """Mocked runner returns pass for every harness -> 5/5."""
        mod = _load_attach_mod()
        ws = self._emit(FIX_GOOD)
        try:
            def all_pass(_path):
                return {"status": "pass", "engine": "mock"}

            report = mod.summarise_campaign(ws, all_pass)
            self.assertEqual(report["family"], "vault")
            self.assertEqual(report["mode"], "campaign")
            self.assertEqual(report["total"], 5)
            self.assertEqual(report["pass"], 5)
            self.assertEqual(report["counterexamples"], [])
            ids = [r["id"] for r in report["results"]]
            self.assertEqual(ids, ["I1", "I2", "I3", "I4", "I5"])
            for r in report["results"]:
                self.assertEqual(r["status"], "pass")
        finally:
            shutil.rmtree(ws.parent, ignore_errors=True)

    def test_bad_fixture_surfaces_counterexample_mocked(self):
        """Mocked runner returns counterexample on I4 -> flagged in report."""
        mod = _load_attach_mod()
        ws = self._emit(FIX_BAD)
        try:
            def counter_on_I4(path):
                name = Path(path).name
                if name == "vault_campaign_I4.t.sol":
                    return {
                        "status": "counterexample",
                        "engine": "mock",
                        "failing_sequence": (
                            "doDeposit(0, 100e18); doWithdraw(1, 50e18); "
                            "doDeposit(2, 10e18);"
                        ),
                    }
                return {"status": "pass", "engine": "mock"}

            report = mod.summarise_campaign(ws, counter_on_I4)
            self.assertEqual(report["total"], 5)
            self.assertEqual(report["pass"], 4)
            self.assertEqual(report["counterexamples"], ["I4"])
            i4 = next(r for r in report["results"] if r["id"] == "I4")
            self.assertEqual(i4["status"], "counterexample")
            self.assertIn("failing_sequence", i4["details"])
        finally:
            shutil.rmtree(ws.parent, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
