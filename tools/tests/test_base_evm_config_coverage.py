#!/usr/bin/env python3
"""Tests for tools/base-evm-config-coverage.py (PR #546 Wave 10 Lane G).

Stdlib-only. Hermetic synthetic Cargo crates + (when present)
real-corpus smoke against external/base/.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "base-evm-config-coverage.py"
CORPUS_DIR = ROOT / "tools" / "baselines" / "a11_precompile_diff"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "base_evm_config_coverage", TOOL
    )
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["base_evm_config_coverage"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()


def _run(args: list, *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(cwd) if cwd else None,
    )


SYNTHETIC_CARGO = textwrap.dedent(
    """\
    [package]
    name = "azul-evm"
    version = "0.1.0"

    [dependencies]
    revm = "13.1.0"
    reth-primitives = { version = "1.2.3", features = ["std"] }
    alloy-primitives = "0.8.0"
    """
)

SYNTHETIC_LIB_RS = textwrap.dedent(
    """\
    //! Synthetic Base / Azul EVM crate fixture for tests.
    use revm::Precompile;
    use reth_primitives::Hardfork;

    /// EIP-7939 CLZ opcode marker.
    pub fn handle_clz_opcode() -> u64 {
        // CLZ count_leading_zeros for u256.
        42
    }

    /// EIP-7951 secp256r1 verify precompile.
    pub fn register_secp256r1_p256() {
        let _addr = address!("0x0000000000000000000000000000000000000100");
        let _pc = Precompile::new();
    }

    /// Activation timestamps.
    const AZUL_ACTIVATION_TIMESTAMP: u64 = 1_730_000_000;
    const PRE_AZUL_TIMESTAMP: u64 = 1_700_000_000;

    pub fn is_azul_active(t: u64) -> bool {
        t >= AZUL_ACTIVATION_TIMESTAMP
    }

    /// Account-Balances-and-Receipts removal marker.
    pub mod account_balances_and_receipts {
        pub fn compute_balances_root() -> [u8; 32] { [0u8; 32] }
    }

    /// EVM config override.
    pub struct BaseEvmConfig;
    impl BaseEvmConfig {
        pub fn configure_evm() {}
    }

    /// Gas-table reference (custom).
    pub const GAS_TABLE: [u64; 256] = [0; 256];
    """
)

SYNTHETIC_BUILD_RS = textwrap.dedent(
    """\
    fn main() {
        println!("cargo:rerun-if-changed=src/lib.rs");
    }
    """
)


def _make_synthetic_workspace() -> Path:
    ws = Path(tempfile.mkdtemp(prefix="a11_ws_"))
    crate_dir = ws / "external" / "base" / "crates" / "execution" / "evm"
    src_dir = crate_dir / "src"
    src_dir.mkdir(parents=True)
    (crate_dir / "Cargo.toml").write_text(SYNTHETIC_CARGO, encoding="utf-8")
    (src_dir / "lib.rs").write_text(SYNTHETIC_LIB_RS, encoding="utf-8")
    (crate_dir / "build.rs").write_text(SYNTHETIC_BUILD_RS, encoding="utf-8")
    return ws


class TestSyntheticCrate(unittest.TestCase):
    """Synthetic Cargo crate citing revm = '...' + Base-specific additions."""

    def test_cargo_pin_parsed(self):
        ws = _make_synthetic_workspace()
        try:
            cargo = (
                ws / "external" / "base" / "crates" / "execution" / "evm"
                / "Cargo.toml"
            )
            pins = _MOD.parse_cargo_pins(cargo)
            self.assertEqual(pins.get("revm"), "13.1.0")
            self.assertEqual(pins.get("reth-primitives"), "1.2.3")
            self.assertEqual(pins.get("alloy-primitives"), "0.8.0")
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_resolve_upstream_pin_prefers_revm(self):
        pins = {"revm": "13.1.0", "reth": "1.0.0"}
        self.assertEqual(_MOD.resolve_upstream_pin(pins), "revm=13.1.0")

    def test_clz_marker_detected(self):
        ws = _make_synthetic_workspace()
        try:
            deltas, _pins = _MOD.scan_workspace(ws)
            tags = {d.base_modification for d in deltas}
            names = {d.precompile_name for d in deltas}
            self.assertIn(_MOD.MOD_TAG_OPCODE_ADD, tags)
            self.assertIn("clz_opcode", names)
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_secp256r1_marker_detected(self):
        ws = _make_synthetic_workspace()
        try:
            deltas, _pins = _MOD.scan_workspace(ws)
            secp = [d for d in deltas if d.precompile_name == "secp256r1_p256"]
            self.assertGreaterEqual(len(secp), 1)
            # Address extraction.
            addrs = [d.address for d in secp if d.address]
            self.assertTrue(any(a.endswith("100") for a in addrs))
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_abr_removal_marker_detected(self):
        ws = _make_synthetic_workspace()
        try:
            deltas, _pins = _MOD.scan_workspace(ws)
            abr = [d for d in deltas
                   if d.base_modification == _MOD.MOD_TAG_RECEIPTS_REMOVAL]
            self.assertGreaterEqual(len(abr), 1)
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_evm_config_override_detected(self):
        ws = _make_synthetic_workspace()
        try:
            deltas, _pins = _MOD.scan_workspace(ws)
            cfg = [d for d in deltas
                   if d.base_modification == _MOD.MOD_TAG_EVM_CONFIG]
            self.assertGreaterEqual(len(cfg), 1)
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_hardfork_timestamp_extracted(self):
        ws = _make_synthetic_workspace()
        try:
            deltas, _pins = _MOD.scan_workspace(ws)
            timestamps = {d.hardfork_active_at_timestamp for d in deltas
                          if d.hardfork_active_at_timestamp}
            # AZUL_ACTIVATION_TIMESTAMP wins because its name matches.
            self.assertIn("1730000000", timestamps)
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_upstream_pin_propagated_to_rows(self):
        ws = _make_synthetic_workspace()
        try:
            deltas, _pins = _MOD.scan_workspace(ws)
            self.assertTrue(deltas, "expected at least one delta row")
            for d in deltas:
                self.assertEqual(d.upstream_reth_pin, "revm=13.1.0")
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_outputs_written(self):
        ws = _make_synthetic_workspace()
        try:
            rc = _run(["--workspace", str(ws)])
            self.assertEqual(rc.returncode, 0, rc.stderr)
            json_path = ws / "critical_hunt" / "precompile_diff" / "a11_precompile_diff_matrix.json"
            md_path = ws / "critical_hunt" / "precompile_diff" / "a11_precompile_diff_matrix.md"
            seed_path = ws / "critical_hunt" / "candidates" / "a11_precompile_diff_seed.json"
            self.assertTrue(json_path.is_file(), "JSON matrix missing")
            self.assertTrue(md_path.is_file(), "Markdown matrix missing")
            self.assertTrue(seed_path.is_file(), "candidate seed missing")
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], _MOD.SCHEMA_VERSION)
            self.assertGreaterEqual(payload["row_count"], 1)
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_seed_compatible_with_critical_matrix_schema(self):
        """Seed JSON must carry candidate_id / impact_mapping / production_path."""
        ws = _make_synthetic_workspace()
        try:
            rc = _run(["--workspace", str(ws)])
            self.assertEqual(rc.returncode, 0, rc.stderr)
            seed_path = ws / "critical_hunt" / "candidates" / "a11_precompile_diff_seed.json"
            data = json.loads(seed_path.read_text(encoding="utf-8"))
            self.assertIn("candidates", data)
            for c in data["candidates"]:
                # base-critical-candidate-matrix.py reads these keys.
                self.assertIn("candidate_id", c)
                self.assertIn("impact_mapping", c)  # default-to-kill: blank
                self.assertEqual(c["impact_mapping"], "")
                self.assertIn("production_path", c)
                self.assertIn("required_proof", c)
                self.assertIn("artifact_refs", c)
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_dedupe_collapses_repeats(self):
        deltas = [
            _MOD.Delta(
                delta_id="x", crate="c", file="f", line=1,
                precompile_name="n", address="", hardfork_active_at_timestamp="",
                upstream_reth_pin="", base_modification=_MOD.MOD_TAG_OPCODE_ADD,
            ),
            _MOD.Delta(
                delta_id="y", crate="c", file="f", line=1,
                precompile_name="n", address="", hardfork_active_at_timestamp="",
                upstream_reth_pin="", base_modification=_MOD.MOD_TAG_OPCODE_ADD,
            ),
        ]
        out = _MOD.dedupe_deltas(deltas)
        self.assertEqual(len(out), 1)

    def test_strict_fails_when_no_pin(self):
        ws = Path(tempfile.mkdtemp(prefix="a11_nopin_"))
        try:
            crate = ws / "external" / "base" / "crates" / "evm"
            (crate / "src").mkdir(parents=True)
            # Cargo.toml without any upstream pin.
            (crate / "Cargo.toml").write_text(
                "[package]\nname = \"x\"\nversion = \"0\"\n", encoding="utf-8"
            )
            (crate / "src" / "lib.rs").write_text(
                "pub fn f() { let _ = secp256r1_verify(); }\n", encoding="utf-8"
            )
            rc = _run(["--workspace", str(ws), "--strict"])
            # Should fail strict because deltas exist but no pin.
            self.assertEqual(rc.returncode, 1, rc.stdout + rc.stderr)
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_empty_workspace_exits_zero(self):
        ws = Path(tempfile.mkdtemp(prefix="a11_empty_"))
        try:
            rc = _run(["--workspace", str(ws)])
            self.assertEqual(rc.returncode, 0, rc.stderr)
            json_path = ws / "critical_hunt" / "precompile_diff" / "a11_precompile_diff_matrix.json"
            self.assertTrue(json_path.is_file())
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["row_count"], 0)
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_invalid_workspace_exits_2(self):
        rc = _run(["--workspace", "/nonexistent/path/zzz"])
        self.assertEqual(rc.returncode, 2)


class TestDifferentialCorpus(unittest.TestCase):
    """Tool ships a bundled differential test-input corpus."""

    def test_corpus_dir_exists(self):
        self.assertTrue(CORPUS_DIR.is_dir(), f"corpus missing: {CORPUS_DIR}")
        diff = CORPUS_DIR / "differential_test_inputs"
        self.assertTrue(diff.is_dir())

    def test_positive_control_count(self):
        diff = CORPUS_DIR / "differential_test_inputs"
        rows = list(diff.glob("pc_*.json"))
        self.assertEqual(len(rows), 5, f"expected 5 positive-control rows, got {len(rows)}")
        for path in rows:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["category"], "positive_control")
            self.assertTrue(data["expected_same_across_revm_and_base"])

    def test_base_specific_count(self):
        diff = CORPUS_DIR / "differential_test_inputs"
        rows = list(diff.glob("bs_*.json"))
        self.assertEqual(len(rows), 5, f"expected 5 base-specific rows, got {len(rows)}")
        targets = set()
        for path in rows:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["category"], "base_specific")
            targets.add(data["delta_target"])
        # Must hit all three known A11 deltas.
        self.assertIn("clz", targets)
        self.assertIn("secp256r1", targets)
        self.assertIn("abr", targets)


class TestRealCorpusSmoke(unittest.TestCase):
    """Smoke-test against external/base/crates/execution/evm/{lib.rs,build.rs}.

    Skipped automatically if the operator has not vendored the Azul tree
    into the workspace; CI runs the synthetic tests above. This is the
    real-corpus check called out in the lane-G spec.
    """

    def test_real_corpus_if_vendored(self):
        # Caller may set AUDITOOOR_A11_REAL_WS to point to a workspace with
        # external/base/ vendored. When unset and no convenient location is
        # available we skip rather than fail.
        import os
        ws_env = os.environ.get("AUDITOOOR_A11_REAL_WS")
        candidates = []
        if ws_env:
            candidates.append(Path(ws_env))
        # Try common operator audit locations.
        home = Path.home()
        for hint in ("audits/base-azul", "audits/base", "audits/azul"):
            candidates.append(home / hint)
        for cand in candidates:
            evm_lib = cand / "external" / "base" / "crates" / "execution" / "evm" / "src" / "lib.rs"
            if evm_lib.is_file():
                deltas, pins = _MOD.scan_workspace(cand)
                self.assertGreater(
                    len(deltas), 0,
                    f"real corpus at {cand} produced zero deltas — scanner regression",
                )
                # If the operator pinned anything, it should be propagated.
                if pins:
                    pinned_rows = [d for d in deltas if d.upstream_reth_pin]
                    self.assertGreater(
                        len(pinned_rows), 0,
                        "pins discovered in Cargo.toml but no row carries one",
                    )
                return
        self.skipTest("no real Azul tree vendored under any expected location")


if __name__ == "__main__":
    unittest.main()
