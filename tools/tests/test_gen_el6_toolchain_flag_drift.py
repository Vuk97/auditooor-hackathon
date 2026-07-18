#!/usr/bin/env python3
"""GEN-EL6 toolchain-flag semantic-drift screen - regression + non-vacuity tests.

Pins tools/toolchain-flag-drift-screen.py: a build/toolchain FLAG that changes
program SEMANTICS (not merely optimization) can silently invalidate a source-
level safety assumption. Rows carry verdict='needs-fuzz' (advisory, NO-CREDIT).

FP-CONTROL matrix (pure fixtures staged into a tempdir so the tool's own
test-path exclusion does not swallow them):
  - rust_fire          : [profile.release] overflow-checks=false + bare arith -> 1 medium
  - rust_defaulted     : release profile, overflow-checks ABSENT (defaulted off) -> 1 medium
  - rust_safe          : overflow-checks=true                                    -> 0 (SILENT)
  - rust_checked_only  : overflow-checks=false BUT only checked_add in source    -> 0 (SILENT)
  - sol_fire_cancun    : evm_version="cancun"                                    -> 1 evmversion-opcode
  - sol_safe_paris     : evm_version="paris" (no new opcode)                     -> 0 (SILENT)
  - sol_viair          : via_ir=true + inline assembly in source                -> 1 viair-codegen
  - sol_drift          : two distinct evm_versions in one config                -> pin-flag-mismatch
  - go_buildtag        : //go:build !prod gating a validation path              -> 1 build-tag-gate

Advisory-first: default exit 0 even with fired rows; --strict / env elevates.

Non-vacuity (test_mutate_overflow_flag / test_mutate_evm_version): the two
mutation checks flip a SEMANTIC flag on an in-memory copy of a fixture config;
the safe original is silent and the mutant newly fires, proving the flag value
(not some always-fire) is load-bearing. This mirrors the real-fleet mutation-
verify executed on near/src/Cargo.toml (overflow-checks true->false) and a
foundry.toml (evm_version paris->cancun).
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "toolchain-flag-drift-screen.py"
FX = ROOT / "tools" / "tests" / "fixtures" / "gen_el6"
SIDE_NAME = "toolchain_flag_drift_hypotheses.jsonl"
SCHEMA = "auditooor.toolchain_flag_drift_hypotheses.v1"
STRICT_ENV = "AUDITOOOR_TOOLCHAIN_FLAG_DRIFT_STRICT"


def _load_tool():
    spec = importlib.util.spec_from_file_location("toolchain_el6", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scan_fixture(tool, name):
    """Stage a fixture ws into a tempdir (so the tool's test-path exclusion,
    which correctly skips anything under tools/tests/fixtures, does not swallow
    it) and return the fired rows."""
    with tempfile.TemporaryDirectory() as td:
        dst = pathlib.Path(td) / name
        shutil.copytree(FX / name, dst)
        return tool.scan_workspace(dst)


class GenEl6MatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_rust_fire_overflow_off(self):
        rows = _scan_fixture(self.tool, "rust_fire")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        r = rows[0]
        self.assertEqual(r["capability"], "GEN_EL6")
        self.assertEqual(r["schema"], SCHEMA)
        self.assertEqual(r["drift_kind"], "overflow-checks-off")
        self.assertEqual(r["lang"], "rust")
        self.assertEqual(r["severity"], "medium")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        # the JOIN must cite the source arithmetic site as the assumption
        self.assertIn("bare integer arithmetic", r["source_assumption"])

    def test_rust_defaulted_off_fires(self):
        rows = _scan_fixture(self.tool, "rust_defaulted")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        self.assertEqual(rows[0]["drift_kind"], "overflow-checks-off")
        self.assertIn("DEFAULTED off", rows[0]["why_severity_anchored"])

    def test_rust_safe_overflow_on_silent(self):
        rows = _scan_fixture(self.tool, "rust_safe")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_rust_checked_only_silent(self):
        # config alone (overflow-checks off) but NO bare arithmetic -> SKIP.
        rows = _scan_fixture(self.tool, "rust_checked_only")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_sol_cancun_opcode_fires(self):
        rows = _scan_fixture(self.tool, "sol_fire_cancun")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        r = rows[0]
        self.assertEqual(r["drift_kind"], "evmversion-opcode")
        self.assertEqual(r["config_value"], "cancun")
        self.assertEqual(r["lang"], "solidity")
        self.assertIn("TSTORE", r["source_assumption"])

    def test_sol_paris_silent(self):
        rows = _scan_fixture(self.tool, "sol_safe_paris")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_sol_viair_with_assembly_fires(self):
        rows = _scan_fixture(self.tool, "sol_viair")
        kinds = [r["drift_kind"] for r in rows]
        self.assertIn("viair-codegen", kinds, kinds)
        # evm_version is paris here, so ONLY the viaIR arm should fire.
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])

    def test_sol_drift_pin_flag_mismatch(self):
        rows = _scan_fixture(self.tool, "sol_drift")
        kinds = [r["drift_kind"] for r in rows]
        self.assertIn("pin-flag-mismatch", kinds, kinds)
        pm = [r for r in rows if r["drift_kind"] == "pin-flag-mismatch"][0]
        self.assertIn("cancun", pm["config_value"])
        self.assertIn("prague", pm["config_value"])
        self.assertEqual(pm["severity"], "medium")

    def test_go_build_tag_gate(self):
        rows = _scan_fixture(self.tool, "go_buildtag")
        self.assertEqual(len(rows), 1, [r["excerpt"] for r in rows])
        r = rows[0]
        self.assertEqual(r["drift_kind"], "build-tag-gate")
        self.assertEqual(r["lang"], "go")
        self.assertIn("prod", r["config_value"])

    def test_every_row_is_anchored(self):
        # FP-control invariant: every fired row carries a drift_kind + a
        # source_assumption + a why anchored to observable semantics, never a
        # bare "flag is set" claim.
        kinds = {"overflow-checks-off", "evmversion-opcode", "build-tag-gate",
                 "viair-codegen", "pin-flag-mismatch"}
        for fx in ("rust_fire", "sol_fire_cancun", "sol_viair", "sol_drift",
                   "go_buildtag"):
            for r in _scan_fixture(self.tool, fx):
                self.assertIn(r["drift_kind"], kinds)
                self.assertTrue(r["source_assumption"])
                self.assertTrue(r["why_severity_anchored"])
                self.assertTrue(r["config_key"])


class GenEl6AdvisoryExitTest(unittest.TestCase):
    """Advisory-first: default exit 0 even with fired rows; --strict elevates."""

    def _run_ws(self, fixture, extra_env=None, strict=False):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td) / "ws"
            shutil.copytree(FX / fixture, ws)
            argv = [sys.executable, str(TOOL), "--workspace", str(ws)]
            if strict:
                argv.append("--strict")
            env = dict(os.environ)
            env.pop(STRICT_ENV, None)
            if extra_env:
                env.update(extra_env)
            proc = subprocess.run(argv, capture_output=True, text=True, env=env)
            side = ws / ".auditooor" / SIDE_NAME
            rows = []
            if side.exists():
                rows = [json.loads(l) for l in side.read_text().splitlines()
                        if l.strip()]
            return proc.returncode, rows, proc.stdout

    def test_default_advisory_exit0_with_sidecar(self):
        rc, rows, out = self._run_ws("rust_fire")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(rows), 1, out)
        self.assertEqual(rows[0]["schema"], SCHEMA)
        self.assertEqual(rows[0]["drift_kind"], "overflow-checks-off")

    def test_strict_flag_elevates(self):
        rc, rows, out = self._run_ws("rust_fire", strict=True)
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(rows), 1)

    def test_strict_env_elevates(self):
        rc, _rows, out = self._run_ws("sol_fire_cancun", extra_env={STRICT_ENV: "1"})
        self.assertEqual(rc, 1, out)

    def test_check_reads_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td) / "ws"
            shutil.copytree(FX / "rust_fire", ws)
            subprocess.run([sys.executable, str(TOOL), "--workspace", str(ws)],
                           capture_output=True, text=True)
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--check",
                 "--json"], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout)
            summ = json.loads(proc.stdout)
            self.assertEqual(summ["source"], "sidecar")
            self.assertEqual(summ["fired"], 1)


class GenEl6NonVacuityTest(unittest.TestCase):
    """Byte-level mutation-verify (mirrors the executed real-fleet flip): flip a
    SEMANTIC flag on an in-memory copy of a fixture config; the safe original is
    silent and the mutant newly fires, proving the FLAG VALUE is load-bearing
    (not a vacuous always-fire on the mere presence of the config key)."""

    def setUp(self):
        self.tool = _load_tool()

    def _stage(self, td, fixture):
        dst = pathlib.Path(td) / "ws"
        shutil.copytree(FX / fixture, dst)
        return dst

    def test_mutate_overflow_flag(self):
        # rust_safe has overflow-checks = true (silent). Flip -> false. Must fire.
        with tempfile.TemporaryDirectory() as td:
            ws = self._stage(td, "rust_safe")
            base = self.tool.scan_workspace(ws)
            self.assertEqual(len(base), 0,
                             "overflow-checks=true baseline must be silent")
            cargo = ws / "src" / "crate" / "Cargo.toml"
            orig = cargo.read_text()
            cargo.write_text(orig.replace("overflow-checks = true",
                                          "overflow-checks = false"))
            mutant = self.tool.scan_workspace(ws)
            self.assertGreaterEqual(
                len(mutant), 1,
                "flipping overflow-checks true->false must newly fire - the "
                "flag value is load-bearing")
            self.assertEqual(mutant[0]["drift_kind"], "overflow-checks-off")
            # byte-identical restore -> silent again
            cargo.write_text(orig)
            self.assertEqual(len(self.tool.scan_workspace(ws)), 0,
                             "restore must return to silent")

    def test_mutate_evm_version(self):
        # sol_safe_paris has evm_version="paris" (silent). Flip -> cancun. Fire.
        with tempfile.TemporaryDirectory() as td:
            ws = self._stage(td, "sol_safe_paris")
            base = self.tool.scan_workspace(ws)
            self.assertEqual(len(base), 0,
                             "evm_version=paris baseline must be silent")
            cfg = ws / "src" / "proj" / "foundry.toml"
            orig = cfg.read_text()
            cfg.write_text(orig.replace('evm_version = "paris"',
                                        'evm_version = "cancun"'))
            mutant = self.tool.scan_workspace(ws)
            self.assertGreaterEqual(
                len(mutant), 1,
                "flipping evm_version paris->cancun must newly fire the "
                "opcode-availability arm")
            self.assertEqual(mutant[0]["drift_kind"], "evmversion-opcode")
            cfg.write_text(orig)
            self.assertEqual(len(self.tool.scan_workspace(ws)), 0,
                             "restore must return to silent")

    def test_source_join_is_load_bearing(self):
        # rust_checked_only is silent because source has no bare arithmetic.
        # Neutralise the source-join gate; the config alone must then fire,
        # proving the JOIN (not the config) is what suppresses it.
        with tempfile.TemporaryDirectory() as td:
            ws = self._stage(td, "rust_checked_only")
            base = self.tool.scan_workspace(ws)
            self.assertEqual(len(base), 0, "checked-only source must be silent")
            self.tool._rust_bare_arith_site = lambda _t: (1, "a + b")
            weakened = self.tool.scan_workspace(ws)
            self.assertGreaterEqual(
                len(weakened), 1,
                "neutralising the bare-arithmetic JOIN must make the "
                "overflow-checks-off config newly fire - the source JOIN is "
                "load-bearing (config alone is not sufficient)")


if __name__ == "__main__":
    unittest.main()
