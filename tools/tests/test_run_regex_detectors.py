"""tests for detectors/run_regex_detectors.py — the L28-B regex-API runner.

Covers:
  1. Discovery loads at least the 6 wave17 regex-API detectors and skips
     non-conforming files (e.g. graveyard / underscore-prefixed dirs).
  2. iter_solidity_sources walks .sol files and skips vendored paths.
  3. End-to-end run() against a tiny fixture tree fires the
     v4-hook-take-before-pricing-state-mutation detector and writes the
     JSON manifest at the expected path.
  4. --detector filter narrows discovery to a single detector.
  5. Manifest schema includes the required keys (schema, target, findings,
     per_detector_counts).

Stdlib only. Uses tempfile.TemporaryDirectory for the synthetic workspace.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RUNNER = REPO / "detectors" / "run_regex_detectors.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("run_regex_detectors_mod", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_regex_detectors_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


# Synthetic source that triggers v4-hook-take-before-pricing-state-mutation.
# Detector requires: file mentions unlockCallback / IUnlockCallback / poolManager,
# AND a `_handle*` fn calls `poolManager.take(...)` (literal name match) BEFORE
# any pricing-storage write (`reserves[...] = ...`). Match position is by byte
# offset within the body.
_SOURCE_TAKE_BEFORE_RESERVES = """\
pragma solidity 0.8.24;

interface IPoolManager {
    function take(address, uint256) external;
}
interface IUnlockCallback {
    function unlockCallback(bytes calldata) external returns (bytes memory);
}

contract Hook is IUnlockCallback {
    IPoolManager poolManager;
    mapping(address => uint256) public reserves;

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        return _handleSwap(data);
    }

    function _handleSwap(bytes calldata data) internal returns (bytes memory) {
        // Bug: take BEFORE updating reserves[]
        poolManager.take(msg.sender, 100);
        reserves[msg.sender] -= 100;  // post-take mutation of pricing storage
        return "";
    }
}
"""

# A clean .sol file that should not trigger the take-before-reserves detector
# (no unlock-callback shape).
_SOURCE_CLEAN = """\
pragma solidity 0.8.24;
contract Plain {
    uint256 public x;
    function set(uint256 v) external { x = v; }
}
"""


class TestDiscovery(unittest.TestCase):
    def test_discovery_finds_wave17_regex_detectors(self):
        mod = _load_runner()
        detectors = mod.discover_detectors(REPO / "detectors")
        names = {name for name, _, _ in detectors}
        # The cataloged wave17 regex detectors should all be discovered.
        expected = {
            "v4-hook-take-before-pricing-state-mutation",
            "exact-output-floor-input-drain",
            "v4-hook-beforeswap-slippage-bypass",
            "v4-settle-without-prior-sync",
            "wrapper-passes-zero-slippage-to-internal-call",
            "dual-direction-swap-math-asymmetry",
            "zero-signal-drain",
        }
        missing = expected - names
        self.assertFalse(missing, f"missing detectors: {missing}")

    def test_discovery_skips_underscore_dirs(self):
        # Quarantine subdirs (leaf starts with `_`) must not be loaded.
        mod = _load_runner()
        detectors = mod.discover_detectors(REPO / "detectors")
        loaded_paths = [str(src) for _, _, src in detectors]
        for p in loaded_paths:
            parts = Path(p).relative_to(REPO / "detectors").parts
            for part in parts:
                self.assertFalse(
                    part.startswith("_"),
                    f"underscore-prefixed path leaked into discovery: {p}",
                )

    def test_name_filter_narrows_to_single(self):
        mod = _load_runner()
        detectors = mod.discover_detectors(
            REPO / "detectors",
            name_filter="exact-output-floor-input-drain",
        )
        self.assertEqual(len(detectors), 1)
        self.assertEqual(detectors[0][0], "exact-output-floor-input-drain")


class TestSourceWalking(unittest.TestCase):
    def test_iter_skips_vendored(self):
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Real.sol").write_text("contract A {}")
            (root / "lib").mkdir()
            (root / "lib" / "Vendored.sol").write_text("contract V {}")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "X.sol").write_text("contract X {}")
            files = sorted(p.name for p in mod.iter_solidity_sources(root))
            self.assertEqual(files, ["Real.sol"])

    def test_iter_handles_single_file(self):
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "X.sol"
            f.write_text("contract X {}")
            files = list(mod.iter_solidity_sources(f))
            self.assertEqual(files, [f])


class TestEndToEnd(unittest.TestCase):
    def test_run_fires_take_before_reserves_and_writes_manifest(self):
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src_dir = ws / "src"
            src_dir.mkdir()
            (src_dir / "Hook.sol").write_text(_SOURCE_TAKE_BEFORE_RESERVES)
            (src_dir / "Plain.sol").write_text(_SOURCE_CLEAN)
            manifest = ws / ".audit_logs" / "regex_detectors_manifest.json"
            rc = mod.run(
                target=src_dir,
                workspace=ws,
                manifest_path=manifest,
                name_filter=None,
                json_only=True,
                no_manifest=False,
            )
            self.assertEqual(rc, 0)
            self.assertTrue(manifest.is_file(), "manifest not written")
            data = json.loads(manifest.read_text())

            # Schema-required keys
            for k in (
                "schema",
                "target",
                "workspace",
                "detectors",
                "files_scanned",
                "findings",
                "per_detector_counts",
            ):
                self.assertIn(k, data, f"missing manifest key: {k}")
            self.assertEqual(data["schema"], "auditooor.regex_detectors_manifest.v1")
            self.assertEqual(data["files_scanned"], 2)

            # Should have at least one finding from the take-before-reserves
            # detector on Hook.sol; clean Plain.sol must not match.
            det_name = "v4-hook-take-before-pricing-state-mutation"
            findings = [f for f in data["findings"] if f["detector"] == det_name]
            self.assertGreaterEqual(
                len(findings), 1,
                f"expected v4-hook-take-before-pricing-state-mutation hit; "
                f"got {data['per_detector_counts']}",
            )
            self.assertIn("Hook.sol", findings[0]["file"])
            self.assertEqual(findings[0]["fp_guardrails_passed"], True)
            self.assertEqual(findings[0]["severity"], "High")

    def test_run_with_filter_runs_only_one_detector(self):
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src_dir = ws / "src"
            src_dir.mkdir()
            (src_dir / "Hook.sol").write_text(_SOURCE_TAKE_BEFORE_RESERVES)
            manifest = ws / ".audit_logs" / "regex_detectors_manifest.json"
            rc = mod.run(
                target=src_dir,
                workspace=ws,
                manifest_path=manifest,
                name_filter="dual-direction-swap-math-asymmetry",
                json_only=True,
                no_manifest=False,
            )
            self.assertEqual(rc, 0)
            data = json.loads(manifest.read_text())
            self.assertEqual(data["detectors"], ["dual-direction-swap-math-asymmetry"])


if __name__ == "__main__":
    unittest.main()
