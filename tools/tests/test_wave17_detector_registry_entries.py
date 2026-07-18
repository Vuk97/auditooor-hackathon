"""Wave17 regex-runner regression test: cataloged regex detectors stay registered.

Background
----------
The wave17 detectors `dual_direction_swap_math_asymmetry`,
`exact_output_floor_input_drain`, `v4_hook_beforeswap_slippage_bypass`,
`v4_hook_take_before_pricing_state_mutation`, `v4_settle_without_prior_sync`,
`wrapper_passes_zero_slippage_to_internal_call`, and `zero_signal_drain`
expose a stdlib-only
`scan(source, file_path)` API, NOT a Slither `AbstractDetector` subclass.
They are auto-discovered and executed by `detectors/run_regex_detectors.py`
(which is auto-fired from `tools/workspace-scan-orchestrator.py` under
`make audit`).

The initial 6 registry entries landed in PR #729 Wave-2 PR-B. The Graph
`zero_signal_drain` seed was promoted later on 2026-05-17 after the detector
already existed on disk but remained recommendation-only in status reporting.
The registry is consulted by `tools/detector-registry-completeness-check.py`
(L28-B advisory) and by tier-filter gating in `detectors/run_custom.py`
(Slither path only). Keeping these entries present closes the catalog-
completeness gap and makes the detectors visible to registry-introspection
tooling.

This test asserts BOTH:
  (a) the detectors are present in `_tier_registry.yaml` with a tier
      value, an `engine: regex` marker, and a `runner` pointer to
      `detectors/run_regex_detectors.py`; AND
  (b) the detectors are still discovered by `run_regex_detectors.py`'s
      path-based loader (i.e. registry entries do not gate discovery; if
      a future refactor accidentally couples them, this test fails fast).

Stdlib + PyYAML only.

synthetic_fixture: false  (asserts real registry + real runner discovery)
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
REGISTRY_PATH = REPO / "detectors" / "_tier_registry.yaml"
RUNNER_PATH = REPO / "detectors" / "run_regex_detectors.py"
DETECTORS_ROOT = REPO / "detectors"


TARGET_DETECTORS = [
    ("dual-direction-swap-math-asymmetry",
     "detectors/wave17/dual_direction_swap_math_asymmetry.py"),
    ("exact-output-floor-input-drain",
     "detectors/wave17/exact_output_floor_input_drain.py"),
    ("v4-hook-beforeswap-slippage-bypass",
     "detectors/wave17/v4_hook_beforeswap_slippage_bypass.py"),
    ("v4-hook-take-before-pricing-state-mutation",
     "detectors/wave17/v4_hook_take_before_pricing_state_mutation.py"),
    ("v4-settle-without-prior-sync",
     "detectors/wave17/v4_settle_without_prior_sync.py"),
    ("wrapper-passes-zero-slippage-to-internal-call",
     "detectors/wave17/wrapper_passes_zero_slippage_to_internal_call.py"),
    ("zero-signal-drain",
     "detectors/wave17/zero_signal_drain.py"),
]


def _load_registry() -> dict:
    """Load `detectors/_tier_registry.yaml`. Skip the test module gracefully
    if PyYAML is not installed (mirrors the rest of the test corpus)."""
    try:
        import yaml  # type: ignore
    except ImportError:  # pragma: no cover
        raise unittest.SkipTest("PyYAML not installed; cannot validate registry")
    with REGISTRY_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_runner():
    """Import detectors/run_regex_detectors.py for discovery introspection."""
    spec = importlib.util.spec_from_file_location(
        "run_regex_detectors_mod_for_wave17_registry_test", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot spec-load {RUNNER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_regex_detectors_mod_for_wave17_registry_test"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestWave17DetectorRegistryEntries(unittest.TestCase):
    """Wave17 regex detectors must be registered + discoverable."""

    def setUp(self) -> None:
        self.registry = _load_registry()
        self.tiers = self.registry.get("tiers", {}) or {}

    def test_registry_file_exists(self) -> None:
        self.assertTrue(REGISTRY_PATH.is_file(),
                        f"registry file missing: {REGISTRY_PATH}")

    def test_each_target_detector_present_in_registry(self) -> None:
        missing = []
        for det_name, _ in TARGET_DETECTORS:
            if det_name not in self.tiers:
                missing.append(det_name)
        self.assertEqual(missing, [],
                         f"detectors missing from registry tiers map: {missing}")

    def test_each_target_detector_has_tier(self) -> None:
        for det_name, _ in TARGET_DETECTORS:
            entry = self.tiers.get(det_name, {})
            self.assertIn("tier", entry,
                          f"{det_name}: missing 'tier' field")
            tier = entry.get("tier")
            self.assertIn(tier, {"S", "E", "A", "B", "D", "PAPER"},
                          f"{det_name}: unknown tier value {tier!r}")

    def test_each_target_detector_marked_regex_engine(self) -> None:
        """These detectors use the stdlib scan() API, not Slither's
        AbstractDetector. They must be tagged engine=regex so registry-
        introspection tooling does not try to dispatch them through
        detectors/run_custom.py."""
        for det_name, _ in TARGET_DETECTORS:
            entry = self.tiers.get(det_name, {})
            engine = entry.get("engine")
            self.assertEqual(engine, "regex",
                             f"{det_name}: engine={engine!r}, expected 'regex' "
                             "(scan-API detectors are not Slither AbstractDetectors)")

    def test_each_target_detector_points_at_regex_runner(self) -> None:
        for det_name, _ in TARGET_DETECTORS:
            entry = self.tiers.get(det_name, {})
            runner = entry.get("runner")
            self.assertEqual(runner, "detectors/run_regex_detectors.py",
                             f"{det_name}: runner={runner!r}, expected "
                             "'detectors/run_regex_detectors.py'")

    def test_each_target_detector_path_exists_on_disk(self) -> None:
        for det_name, rel_path in TARGET_DETECTORS:
            entry = self.tiers.get(det_name, {})
            registered_path = entry.get("detector_path")
            self.assertEqual(registered_path, rel_path,
                             f"{det_name}: detector_path={registered_path!r}, "
                             f"expected {rel_path!r}")
            abs_path = REPO / rel_path
            self.assertTrue(abs_path.is_file(),
                            f"{det_name}: detector file does not exist at "
                            f"{abs_path}")

    def test_each_target_detector_lists_wave17(self) -> None:
        for det_name, _ in TARGET_DETECTORS:
            entry = self.tiers.get(det_name, {})
            waves = entry.get("waves", []) or []
            self.assertIn("wave17", waves,
                          f"{det_name}: waves={waves!r} does not include "
                          "'wave17'")

    def test_runner_discovers_each_target_detector(self) -> None:
        """Registry entries are catalog metadata. Discovery is path-based
        in run_regex_detectors.py. Assert the path-based loader still finds
        all target detectors — this guards against a future regression where a refactor
        accidentally couples registry entries to discovery."""
        runner = _load_runner()
        discovered = runner.discover_detectors(DETECTORS_ROOT)
        discovered_names = {name for name, _mod, _src in discovered}
        for det_name, _ in TARGET_DETECTORS:
            self.assertIn(det_name, discovered_names,
                          f"{det_name}: not discovered by "
                          f"run_regex_detectors.discover_detectors()")


if __name__ == "__main__":
    unittest.main()
